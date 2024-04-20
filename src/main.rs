use anyhow::Ok;
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let j = json!(
        [
            {
                "a":1,
                "b":2
            },
            {
                "a":2,
                "b":3
            }
        ]
    );

    let j2 = json!(
        {
            "_root":j
        }
    );

    println!("res is {}", j);
    let rs = toml::to_string(&j2)?;
    println!("result: {:?}", rs);
    Ok(())
}
