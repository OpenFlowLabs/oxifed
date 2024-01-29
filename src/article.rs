use async_graphql::SimpleObject;

use crate::prisma::article::Data;

#[derive(Clone, SimpleObject)]
pub struct Article {
    pub descriptor: String,
    pub title: String,
    pub content: String,
    pub content_html: String,
    pub author: String,
    pub draft: bool,
    pub tags: Vec<String>,
}

impl From<Data> for Article {
    fn from(value: Data) -> Self {
        Self {
            descriptor: value.descriptor,
            content: value.content,
            content_html: value.content_html,
            author: value
                .author
                .map_or("undefined".to_owned(), |author| author.handle),
            title: value.title,
            draft: value.draft,
            tags: value.tags,
        }
    }
}
