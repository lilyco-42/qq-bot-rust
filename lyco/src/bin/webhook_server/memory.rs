//! 记忆层：Turso（SQLite 兼容的 Rust 重写）持久化 —— 人类式记忆模型。
//!
//! # 为什么是「人类式」
//!
//! 需求原话：「像人类一样，虽然会忘记今天吃了什么，但记得一些其他的东西」。
//! 对应到模型上就是**重要度驱动的半衰期 + 频次强化**：
//!
//! - **遗忘**：强度按 `strength × 2^(-Δt / half_life)` 指数衰减，
//!   `half_life = 7 天 × importance²`。重要度低的闲聊（0.3）半衰期约 0.6 天，
//!   隔夜就淡了；重要事实（2.0）半衰期约 28 天，核心事实（3.0）约 63 天。
//!   平方关系是关键——它把「重要 vs 琐碎」的留存差距拉开，而非线性平移。
//! - **强化**：同一件事再次被问到或检索命中时 `freq += 1`，强度回补
//!   `strength = min(1.0, strength + 0.4)`。反复出现的事自然沉淀为长期记忆。
//! - **检索排序**：`score = importance × ln(1+freq) × 有效强度`。
//!   `ln` 让频次边际收益递减（被提 100 次不会压过真正重要的事）。
//!
//! # 存储约定
//!
//! 浮点（`importance`/`strength`）以 **×1000 定点整数**入库：只用已验证过的
//! `as_integer()`/`as_text()` 取值，绕开 REAL 取值 API 的版本差异。
//! 可选字段用空串表示「无」，避免 `Option` 绑定的不确定性。
//!
//! # 并发约定
//!
//! 接收端 bin 是同步的（std 线程 + ureq），Turso 是 async；runtime 收在库内，
//! DB 调用以 `block_on` 进入，不把 async 传染到请求链路。
//! `Rows` 游标借用连接，因此「加锁 → 查询 → 收完行」必须在**同一个**
//! `block_on` 内完成（见 [`Store::query`]）。

/// 定点精度：浮点 ×1000 后以 INTEGER 存储。
const SCALE: i64 = 1000;
/// `importance = 1.0` 时的半衰期（天）。
const HALF_LIFE_BASE_DAYS: f64 = 7.0;
/// 命中一次的强度回补（定点 0.4）。
const STRENGTH_BOOST: i64 = 400;
/// 低于该有效强度视为已遗忘（定点 0.02），可被清理。
const FORGOTTEN: i64 = 20;

/// 记忆分类：群内问答沉淀。
pub const KIND_ISSUE: &str = "issue";
/// 记忆分类：显式记下的重要事实（`/记`）。
pub const KIND_FACT: &str = "fact";
/// 记忆分类：群默认话题。
pub const KIND_TOPIC: &str = "topic";

/// 一条记忆。
///
/// 字段与 `memories` 表一一对应。其中 `subject`/`scope` 只服务去重与作用域
/// 隔离、不进入展示文案，故整体允许「字段未被读取」。
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Memory {
    /// 主键。
    pub id: i64,
    /// 分类（[`KIND_ISSUE`] 等）。
    pub kind: String,
    /// 作用域：群/单聊 openid，或 `*` 表示全局。
    pub scope: String,
    /// 归一化主题（去重键）。
    pub subject: String,
    /// 正文（问题或事实）。
    pub content: String,
    /// bot 当时的回答（`issue` 类）。
    pub answer: String,
    /// 提问者标识（用于「同一个人问过吗」）。
    pub actor: String,
    /// 基础重要度（0.1 琐碎 … 3.0 核心）。
    pub importance: f64,
    /// 出现/被命中频次。
    pub freq: i64,
    /// 当前记忆强度 0..=1（命中回补，随时间衰减）。
    pub strength: f64,
    /// 首次记录时间（unix 秒）。
    pub created_at: i64,
    /// 最近一次命中时间（unix 秒）。
    pub last_seen_at: i64,
}

impl Memory {
    /// 当前有效强度（含时间衰减）。
    pub fn effective(&self, now: i64) -> f64 {
        decayed(self.strength, self.importance, self.last_seen_at, now)
    }

    /// 检索评分：重要度 × 频次强化 × 有效强度。
    pub fn score(&self, now: i64) -> f64 {
        self.importance * (1.0 + self.freq as f64).ln() * self.effective(now)
    }
}

/// 指数遗忘：`strength × 2^(-Δt / half_life)`，半衰期随重要度平方增长。
///
/// 纯函数（无 IO/无时钟），便于单测钉住曲线形状。
fn decayed(strength: f64, importance: f64, last_seen_at: i64, now: i64) -> f64 {
    let days = (now.saturating_sub(last_seen_at).max(0) as f64) / 86_400.0;
    let half_life = (HALF_LIFE_BASE_DAYS * importance * importance).max(0.05);
    strength * 2f64.powf(-days / half_life)
}

/// 归一化主题：去空白 + 截断（去重键，不用于展示）。
fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<String>()
        .chars()
        .take(60)
        .collect()
}

/// 记忆库（Turso 本地文件 + tokio runtime）。
pub struct Store {
    rt: tokio::runtime::Runtime,
    /// `Database` 需与 `Connection` 同生命周期，故一并持有。
    _db: turso::Database,
    conn: tokio::sync::Mutex<turso::Connection>,
}

impl Store {
    /// 打开（或创建）记忆库并建表。
    pub fn open(path: &str) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("build tokio runtime: {err}"))?;
        let db = rt
            .block_on(async { turso::Builder::new_local(path).build().await })
            .map_err(|err| format!("open turso db {path}: {err}"))?;
        let conn = db
            .connect()
            .map_err(|err| format!("connect turso db: {err}"))?;
        let store = Self {
            rt,
            _db: db,
            conn: tokio::sync::Mutex::new(conn),
        };
        for sql in CREATE_SQL {
            store.exec(sql)?;
        }
        Ok(store)
    }

    /// 执行无参数语句（建表/索引/删除）。
    fn exec(&self, sql: &str) -> Result<(), String> {
        self.rt.block_on(async {
            let conn = self.conn.lock().await;
            conn.execute(sql, ())
                .await
                .map_err(|err| format!("turso exec: {err}"))?;
            Ok::<(), String>(())
        })
    }

    /// 收完一个查询的全部行。
    ///
    /// `Rows` 借用连接与锁，跨越两次 `block_on` 会悬垂，故「加锁 → 查询 → 收行」
    /// 必须同处一个 `block_on`：调用点负责加锁与查询，这里只负责收完。
    /// 参数一律以元组直接传（turso 已为元组实现绑定，无需自造 trait）。
    async fn collect_rows(mut rows: turso::Rows) -> Result<Vec<Vec<turso::Value>>, String> {
        let mut out = Vec::new();
        loop {
            let next = rows.next().await;
            match next {
                Ok(Some(row)) => {
                    let mut values = Vec::new();
                    let mut index = 0;
                    while let Ok(value) = row.get_value(index) {
                        values.push(value);
                        index += 1;
                    }
                    out.push(values);
                }
                Ok(None) => break,
                Err(err) => return Err(format!("turso row: {err}")),
            }
        }
        Ok(out)
    }

    /// 记一条记忆。
    ///
    /// 同 `scope` + 同 `subject` + 同 `kind` 视为「同一件事再次发生」：
    /// 频次 +1、强度回补、刷新回答与时间；否则新建。
    /// 返回 `(是否新建, 当前频次)`。
    #[allow(clippy::too_many_arguments)]
    pub fn remember(
        &self,
        kind: &str,
        scope: &str,
        content: &str,
        answer: &str,
        actor: &str,
        importance: f64,
        now: i64,
    ) -> Result<(bool, i64), String> {
        let subject = normalize(content);
        if subject.is_empty() {
            return Err("empty memory content".to_string());
        }
        let importance_fixed = (importance * SCALE as f64).round() as i64;

        // 先查是否已存在同一件事。
        let existing = self.rt.block_on(async {
            let conn = self.conn.lock().await;
            let rows = conn
                .query(
                    "SELECT id, freq, strength FROM memories \
                     WHERE scope = ?1 AND kind = ?2 AND subject = ?3",
                    (scope.to_string(), kind.to_string(), subject.clone()),
                )
                .await
                .map_err(|err| format!("turso query: {err}"))?;
            Self::collect_rows(rows).await
        })?;

        if let Some(row) = existing.into_iter().next() {
            let id = int_col(&row, 0);
            let freq = int_col(&row, 1) + 1;
            let strength = (int_col(&row, 2) + STRENGTH_BOOST).min(SCALE);
            self.rt.block_on(async {
                let conn = self.conn.lock().await;
                conn.execute(
                    "UPDATE memories SET freq = ?1, strength = ?2, last_seen_at = ?3, \
                     answer = CASE WHEN ?4 = '' THEN answer ELSE ?4 END, \
                     importance = MAX(importance, ?5), \
                     actor = CASE WHEN ?6 = '' THEN actor ELSE ?6 END \
                     WHERE id = ?7",
                    (
                        freq,
                        strength,
                        now,
                        answer.to_string(),
                        importance_fixed,
                        actor.to_string(),
                        id,
                    ),
                )
                .await
                .map_err(|err| format!("turso reinforce: {err}"))?;
                Ok::<(), String>(())
            })?;
            return Ok((false, freq));
        }

        self.rt.block_on(async {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT INTO memories \
                 (kind, scope, subject, content, answer, actor, importance, freq, strength, created_at, last_seen_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                (
                    kind.to_string(),
                    scope.to_string(),
                    subject.clone(),
                    content.to_string(),
                    answer.to_string(),
                    actor.to_string(),
                    importance_fixed,
                    1_i64,
                    SCALE,
                    now,
                    now,
                ),
            )
            .await
            .map_err(|err| format!("turso insert: {err}"))?;
            Ok::<(), String>(())
        })?;
        Ok((true, 1))
    }

    /// 回忆：按关键词检索，返回按 [`Memory::score`] 排序的 top N。
    ///
    /// `scope` 命中自身或全局 `*`；`actor` 为空表示不过滤提问者
    /// （非空即「之前是不是同一个人问过」）。
    /// 返回的条目会被**强化**（频次+1、强度回补）——被想起的记忆会变清晰。
    pub fn recall(
        &self,
        scope: &str,
        keyword: &str,
        actor: &str,
        now: i64,
        limit: usize,
    ) -> Result<Vec<Memory>, String> {
        let pattern = format!("%{}%", keyword.trim());
        let rows = self.rt.block_on(async {
            let conn = self.conn.lock().await;
            let rows = conn
                .query(
                    "SELECT id, kind, scope, subject, content, answer, actor, importance, freq, \
                     strength, created_at, last_seen_at FROM memories \
                     WHERE (scope = ?1 OR scope = '*') \
                       AND (subject LIKE ?2 OR content LIKE ?2 OR answer LIKE ?2) \
                       AND (?3 = '' OR actor = ?3)",
                    (scope.to_string(), pattern.clone(), actor.to_string()),
                )
                .await
                .map_err(|err| format!("turso query: {err}"))?;
            Self::collect_rows(rows).await
        })?;

        let mut items = rows.iter().map(|row| row_to_memory(row)).collect::<Vec<_>>();
        items.sort_by(|a, b| {
            b.score(now)
                .partial_cmp(&a.score(now))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        items.truncate(limit);
        // 命中即强化（此刻被想起 → 记得更牢）。
        for item in &items {
            self.reinforce(item.id, now)?;
        }
        Ok(items)
    }

    /// 强化单条记忆（频次+1、强度回补、刷新时间）。
    fn reinforce(&self, id: i64, now: i64) -> Result<(), String> {
        self.rt.block_on(async {
            let conn = self.conn.lock().await;
            conn.execute(
                "UPDATE memories SET freq = freq + 1, \
                 strength = MIN(?1, strength + ?2), last_seen_at = ?3 WHERE id = ?4",
                (SCALE, STRENGTH_BOOST, now, id),
            )
            .await
            .map_err(|err| format!("turso reinforce: {err}"))?;
            Ok::<(), String>(())
        })
    }

    /// 遗忘清理：删除有效强度已衰减到阈值以下的记忆，返回清理条数。
    ///
    /// 衰减依赖 `importance`，SQL 内不好直接算，故在 Rust 侧判定后按 id 删除
    /// （bot 记忆量级很小，全量扫描可接受）。
    pub fn forget(&self, now: i64) -> Result<usize, String> {
        let rows = self.rt.block_on(async {
            let conn = self.conn.lock().await;
            let rows = conn
                .query("SELECT id, importance, strength, last_seen_at FROM memories", ())
                .await
                .map_err(|err| format!("turso query: {err}"))?;
            Self::collect_rows(rows).await
        })?;
        let mut doomed = Vec::new();
        for row in &rows {
            let importance = int_col(row, 1) as f64 / SCALE as f64;
            let strength = int_col(row, 2) as f64 / SCALE as f64;
            let last_seen = int_col(row, 3);
            let effective = decayed(strength, importance, last_seen, now) * SCALE as f64;
            if effective < FORGOTTEN as f64 {
                doomed.push(int_col(row, 0));
            }
        }
        for id in &doomed {
            self.rt.block_on(async {
                let conn = self.conn.lock().await;
                conn.execute("DELETE FROM memories WHERE id = ?1", (*id,))
                    .await
                    .map_err(|err| format!("turso delete: {err}"))?;
                Ok::<(), String>(())
            })?;
        }
        Ok(doomed.len())
    }

    /// 统计：总条数 + 各分类条数（供 `/忆` 概览）。
    pub fn stats(&self) -> Result<(i64, Vec<(String, i64)>), String> {
        let total_rows = self.rt.block_on(async {
            let conn = self.conn.lock().await;
            let rows = conn
                .query("SELECT count(*) FROM memories", ())
                .await
                .map_err(|err| format!("turso query: {err}"))?;
            Self::collect_rows(rows).await
        })?;
        let total = total_rows.first().map(|row| int_col(row, 0)).unwrap_or(0);
        let kind_rows = self.rt.block_on(async {
            let conn = self.conn.lock().await;
            let rows = conn
                .query("SELECT kind, count(*) FROM memories GROUP BY kind", ())
                .await
                .map_err(|err| format!("turso query: {err}"))?;
            Self::collect_rows(rows).await
        })?;
        let mut kinds = Vec::new();
        for row in &kind_rows {
            kinds.push((text_col(row, 0), int_col(row, 1)));
        }
        Ok((total, kinds))
    }
}

/// 建表与索引（幂等）。
const CREATE_SQL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS memories (
        id           INTEGER PRIMARY KEY,
        kind         TEXT    NOT NULL,
        scope        TEXT    NOT NULL,
        subject      TEXT    NOT NULL,
        content      TEXT    NOT NULL,
        answer       TEXT    NOT NULL DEFAULT '',
        actor        TEXT    NOT NULL DEFAULT '',
        importance   INTEGER NOT NULL,
        freq         INTEGER NOT NULL,
        strength     INTEGER NOT NULL,
        created_at   INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_mem_scope_kind ON memories(scope, kind)",
    "CREATE INDEX IF NOT EXISTS idx_mem_subject ON memories(subject)",
    "CREATE INDEX IF NOT EXISTS idx_mem_actor ON memories(actor)",
];

/// 取整型列（越界/类型不符时为 0，不 panic）。
fn int_col(row: &[turso::Value], index: usize) -> i64 {
    row.get(index)
        .and_then(|value| value.as_integer())
        .copied()
        .unwrap_or(0)
}

/// 取文本列（越界/类型不符时为空串，不 panic）。
fn text_col(row: &[turso::Value], index: usize) -> String {
    row.get(index)
        .and_then(|value| value.as_text())
        .cloned()
        .unwrap_or_default()
}

/// 行 → [`Memory`]（定点整数还原为浮点）。
fn row_to_memory(row: &[turso::Value]) -> Memory {
    Memory {
        id: int_col(row, 0),
        kind: text_col(row, 1),
        scope: text_col(row, 2),
        subject: text_col(row, 3),
        content: text_col(row, 4),
        answer: text_col(row, 5),
        actor: text_col(row, 6),
        importance: int_col(row, 7) as f64 / SCALE as f64,
        freq: int_col(row, 8),
        strength: int_col(row, 9) as f64 / SCALE as f64,
        created_at: int_col(row, 10),
        last_seen_at: int_col(row, 11),
    }
}

#[cfg(test)]
mod tests {
    use super::{FORGOTTEN, HALF_LIFE_BASE_DAYS, SCALE, decayed, normalize};

    /// 半衰期：经过一个半衰期，强度应恰好减半。
    #[test]
    fn half_life_halves_strength() {
        let day = 86_400_i64;
        let elapsed = (HALF_LIFE_BASE_DAYS * day as f64) as i64;
        let after = decayed(1.0, 1.0, 0, elapsed);
        assert!((after - 0.5).abs() < 1e-6, "after={after}");
    }

    /// 重要度平方效应：琐碎事比重要事忘得快得多。
    #[test]
    fn trivial_fades_far_faster_than_important() {
        let day = 86_400_i64;
        // 用 3 天拉开平方重要度的衰减差：0.3 的有效强度约 0.037，
        // 2.0 的约 0.928。原测试只经过 1 天却要求 trivial < 0.1，数学上不成立。
        let trivial = decayed(1.0, 0.3, 0, 3 * day); // 半衰期 ≈0.63 天
        let important = decayed(1.0, 2.0, 0, 3 * day); // 半衰期 ≈28 天
        assert!(trivial < 0.1, "trivial should fade fast: {trivial}");
        assert!(important > 0.9, "important should persist: {important}");
        assert!(important > trivial * 10.0);
    }

    /// 强化：接近饱和的强度回补后封顶在 1.0，不会溢出。
    #[test]
    fn reinforce_saturates_at_one() {
        let strength = (200_i64 + 400).min(SCALE) as f64 / SCALE as f64;
        assert!((strength - 0.6).abs() < 1e-9, "strength={strength}");
        let boosted = (900_i64 + 400).min(SCALE);
        assert_eq!(boosted, SCALE, "must clamp to 1.0");
    }

    /// 归一化：去空白并截断，作为去重键稳定。
    #[test]
    fn normalize_strips_whitespace_and_truncates() {
        assert_eq!(normalize("  卫戍 协议 掉线  "), "卫戍协议掉线");
        let long = "字".repeat(200);
        assert_eq!(normalize(&long).chars().count(), 60);
    }

    /// 遗忘阈值：长期不碰的琐碎记忆应跌破清理线，重要记忆应存活。
    #[test]
    fn long_untouched_memory_fades_by_importance() {
        let day = 86_400_i64;
        let trivial = decayed(1.0, 0.3, 0, 10 * day) * SCALE as f64;
        let important = decayed(1.0, 2.0, 0, 10 * day) * SCALE as f64;
        assert!(trivial < FORGOTTEN as f64, "should be forgotten: {trivial}");
        assert!(important > FORGOTTEN as f64, "should survive: {important}");
    }
}
