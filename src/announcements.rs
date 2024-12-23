use std::{sync::LazyLock, time::Duration};

use anyhow::Context;
use chrono::{DateTime, NaiveDate, Utc};
use moka::future::Cache;
use regex::Regex;

async fn get_raw_announcements() -> anyhow::Result<Vec<(String, String)>> {
    let resp = reqwest::get(format!("https://gist.githubusercontent.com/nullchinchilla/b99b14bbc6090a423c62c6b29b9d06ca/raw/geph-announcements.md?bust={}", rand::random::<u64>())).await?;
    let resp = resp.bytes().await?;
    let resp = String::from_utf8_lossy(&resp);
    let re = Regex::new(r"T: (\d{4}-\d{2}-\d{2})").unwrap();

    let mut v = vec![];
    for chunk in resp.split("---") {
        let captures = re.captures(chunk).context("missing date string")?;
        let date_str = captures.get(1).context("missing capture in date string")?;
        let cleaned_text = re.replace(&resp, "");
        v.push((date_str.as_str().to_string(), cleaned_text.to_string()));
    }
    Ok(v)
}

pub async fn get_announcements_rss() -> anyhow::Result<String> {
    static CACHE: LazyLock<Cache<(), String>> = LazyLock::new(|| {
        Cache::builder()
            .time_to_live(Duration::from_secs(30))
            .build()
    });
    CACHE.try_get_with((), async move {
    let raw = get_raw_announcements().await?;
    let mut inner = "".to_string();
    for (date, raw_md) in raw {
        let mut raw_html = "".to_string();
        pulldown_cmark::html::push_html(&mut raw_html, pulldown_cmark::Parser::new(&raw_md));
        let raw_html_escaped = html_escape::encode_safe(&raw_html);
        let pub_date = convert_date(&date)?;
        inner.push_str(&format!("<item><title>New</title><link>https://t.me/gephannounce</link><description>{raw_html_escaped}</description><pubDate>{pub_date}</pubDate></item>\n\n"));
    }
    let res = format!(
        r#"
<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
    <channel>
        <title>gephannounce-mirror</title>
        <link>https://t.me/gephannounce_mirror</link>
        <description>Telegram Channel for gephannounce-mirror</description>
        {inner}
    </channel>
</rss>
    "#
    )
    .trim()
    .to_string();
    anyhow::Ok(res)
}).await.map_err(|e| anyhow::anyhow!(e))
}

fn convert_date(input: &str) -> Result<String, chrono::ParseError> {
    // Parse the input string into a NaiveDate
    let naive_date = NaiveDate::parse_from_str(input, "%Y-%m-%d")?;

    // Create a DateTime<Utc> from the NaiveDate, setting the time to 12:00:00
    let datetime = DateTime::<Utc>::from_utc(naive_date.and_hms(12, 0, 0), Utc);

    // Format the DateTime into the desired output string
    let format_string = "%a, %d %b %Y %H:%M:%S +0000";
    let formatted = datetime.format(format_string).to_string();

    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcements() {
        smolscale::block_on(async move {
            let announcements = get_announcements_rss().await.unwrap();
            eprintln!("{}", announcements);
        });
    }
}
