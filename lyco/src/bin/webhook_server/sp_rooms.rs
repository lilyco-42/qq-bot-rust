//! Dedicated read-only Stronghold room directory client.
//! Never use the general-purpose web-fetch tool for this credentialed request.
use serde_json::Value;
use std::time::Duration;

fn display_name(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).take(16).collect()
}

pub(crate) fn render_rooms(raw: &str) -> Result<String, &'static str> {
    let doc: Value = serde_json::from_str(raw).map_err(|_| "响应不是有效 JSON")?;
    if doc.get("ok").and_then(Value::as_bool) != Some(true)
        || doc.get("schemaVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err("服务版本不兼容或返回错误");
    }
    let rooms = doc.get("rooms").and_then(Value::as_array).ok_or("缺少 rooms 列表")?;
    let total = doc.get("total").and_then(Value::as_u64).ok_or("缺少 total 数量")?;
    let mut out = format!("卫戍协议等待房间：共 {total} 间");
    if rooms.is_empty() {
        out.push_str("\n暂无等待中的联机房间。");
    }
    for room in rooms.iter().take(10) {
        let code = room.get("code").and_then(Value::as_str).ok_or("房间号缺失")?;
        if code.len() != 4 || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return Err("房间号格式不合法");
        }
        let difficulty = match room.get("difficulty").and_then(Value::as_str).unwrap_or("") {
            "FUNNY" => "标准模拟",
            "NORMAL" => "险境模拟",
            "HARD" => "绝境模拟",
            "ABYSS" => "终极模拟",
            _ => "未知难度",
        };
        let count = room.get("occupancy").and_then(Value::as_u64).ok_or("人数缺失")?;
        let capacity = room.get("capacity").and_then(Value::as_u64).ok_or("容量缺失")?;
        let joinable = room.get("joinable").and_then(Value::as_bool).unwrap_or(false);
        out.push_str(&format!(
            "\n【{code}】{difficulty} · {count}/{capacity} 人 · {}",
            if joinable { "可加入" } else { "已满" }
        ));
        if let Some(players) = room.get("players").and_then(Value::as_array) {
            let names = players.iter().take(4).filter_map(|p| p.get("name").and_then(Value::as_str))
                .map(display_name).collect::<Vec<_>>();
            if !names.is_empty() { out.push_str(&format!("\n玩家：{}", names.join("、"))); }
        }
        if room.pointer("/strategy/aiPicksLast").and_then(Value::as_bool) == Some(true) {
            out.push_str("\n策略：真人先选，AI 最后选");
        }
    }
    if total > rooms.len() as u64 {
        out.push_str("\n（这里只显示部分房间）");
    }
    Ok(out)
}

/// URL and secret belong to the administrator, never to end-user messages.
/// At most a bounded single GET; no retries, redirects or write methods.
pub(crate) fn query_rooms(url: &str, token: &str) -> String {
    if url.is_empty() || token.len() < 32 {
        return "游戏房间查询未配置：管理员需设置 SP_ROOM_API_URL 与 SP_ROOM_API_TOKEN".into();
    }
    if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1:") {
        return "游戏房间接口必须使用 HTTPS".into();
    }
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).redirects(0).build();
    let response = agent.get(url).set("Authorization", &format!("Bearer {token}")).call();
    let Ok(response) = response else {
        return "游戏房间接口暂时不可用，请稍后再试".into();
    };
    match response.into_string() {
        Ok(body) => match render_rooms(&body) {
            Ok(msg) => msg,
            Err(_) => "游戏房间响应格式异常，未展示未经确认的数据".into(),
        },
        Err(_) => "游戏房间响应读取失败".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::render_rooms;

    #[test]
    fn renders_waiting_room_and_real_strategy_field() {
        let json = r#"{"ok":true,"schemaVersion":1,"total":1,"rooms":[
          {"code":"ABCD","difficulty":"HARD","occupancy":2,"capacity":4,"joinable":true,
           "players":[{"name":"博士甲"},{"name":"AI·阿米娅"}],"strategy":{"aiPicksLast":true}}
        ]}"#;
        let out = render_rooms(json).unwrap();
        for needle in ["ABCD", "绝境模拟", "2/4 人", "博士甲", "AI·阿米娅", "真人先选"] {
            assert!(out.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn rejects_errors_version_drift_and_untrusted_room_codes() {
        assert!(render_rooms(r#"{"ok":false,"error":{"code":"UNAUTHORIZED"}}"#).is_err());
        assert!(render_rooms(r#"{"ok":true,"schemaVersion":2,"total":0,"rooms":[]}"#).is_err());
        assert!(render_rooms(r#"{"ok":true,"schemaVersion":1,"total":1,"rooms":[{"code":"<svg","occupancy":1,"capacity":4}]}"#).is_err());
    }

    #[test]
    fn empty_room_directory_is_not_an_error() {
        let out = render_rooms(r#"{"ok":true,"schemaVersion":1,"total":0,"rooms":[]}"#).unwrap();
        assert!(out.contains("暂无等待"));
    }
}
