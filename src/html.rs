//! HTML utility functions.

/// Extract the `<title>` text from an HTML document.
pub fn extract_title(body: &str) -> Option<String> {
    let doc = scraper::Html::parse_document(body);
    let sel = scraper::Selector::parse("title").ok()?;
    doc.select(&sel)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_title() {
        let html = "<html><head><title>Hello World</title></head></html>";
        assert_eq!(extract_title(html), Some("Hello World".to_string()));
    }

    #[test]
    fn extract_missing_title() {
        let html = "<html><head></head></html>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn extract_empty_title() {
        let html = "<html><head><title>  </title></head></html>";
        assert_eq!(extract_title(html), None);
    }
}
