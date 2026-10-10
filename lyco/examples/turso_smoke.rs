//! Turso（SQLite 的 Rust 重写）接入冒烟验证。
//!
//! 目的：在写正式记忆模块前，先钉死 `turso` 0.8.2 的真实 API 形态
//! （`Builder::new_local` / `Database::connect` 是否 async / `rows.next()` /
//! `Value` 取值），避免照抄旧版文档（README 示例停留在 0.4.3）踩空。
//!
//! 同时验证：纯 Rust 实现 → 无 C 依赖，`cargo zigbuild --target
//! aarch64-unknown-linux-musl` 静态交叉编译不受影响。

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 接收端 bin 是同步的（std 线程 + ureq）；Turso 是 async。
    // 因此用一个常驻的多线程 runtime，DB 调用以 block_on 进入，
    // 不把 async 传染到整个请求链路。
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        // 内存库：只验证 API，不落盘。
        let db = turso::Builder::new_local(":memory:").build().await?;
        let conn = db.connect()?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS memories (id INTEGER PRIMARY KEY, kind TEXT, content TEXT, freq INTEGER)",
            (),
        )
        .await?;

        let affected = conn
            .execute(
                "INSERT INTO memories (kind, content, freq) VALUES (?1, ?2, ?3)",
                ("issue", "卫戍协议掉线", 1_i64),
            )
            .await?;
        println!("inserted rows={affected}");

        let mut rows = conn
            .query("SELECT id, kind, content, freq FROM memories", ())
            .await?;
        while let Some(row) = rows.next().await? {
            let id = row.get_value(0)?;
            let kind = row.get_value(1)?;
            let content = row.get_value(2)?;
            let freq = row.get_value(3)?;
            println!(
                "row id={:?} kind={:?} content={:?} freq={:?}",
                id.as_integer(),
                kind.as_text(),
                content.as_text(),
                freq.as_integer(),
            );
        }

        // 聚合与排序（记忆评分排序会用到）。
        let mut rows = conn
            .query("SELECT count(*) FROM memories", ())
            .await?;
        if let Some(row) = rows.next().await? {
            let n = row.get_value(0)?;
            println!("count={:?}", n.as_integer());
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
