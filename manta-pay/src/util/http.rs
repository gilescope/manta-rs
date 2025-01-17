// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! HTTP Utilities

use manta_util::serde::{de::DeserializeOwned, Serialize};

pub use reqwest::{Error, IntoUrl, Method, Response, Url};

/// Asynchronous HTTP Client
///
/// This client is a wrapper around [`reqwest::Client`] with a known server URL.
pub struct Client {
    /// Server URL
    pub server_url: Url,

    /// Base HTTP Client
    pub client: reqwest::Client,
}

impl Client {
    /// Builds a new HTTP [`Client`] that connects to `server_url`.
    #[inline]
    pub fn new<U>(server_url: U) -> Result<Self, Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            client: reqwest::Client::builder().build()?,
            server_url: server_url.into_url()?,
        })
    }

    /// Sends a new request asynchronously of type `command` with query string `request`.
    #[inline]
    pub async fn request<T, R>(
        &self,
        method: Method,
        command: &str,
        request: &T,
    ) -> Result<R, Error>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        self.client
            .request(
                method,
                self.server_url
                    .join(command)
                    .expect("Building the URL is not allowed to fail."),
            )
            .json(request)
            .send()
            .await?
            .json()
            .await
    }

    // TODO: Investigate a way to have a uniform interface for GET and POST. For now, all
    //       implementations should use POST for all methods.
    //
    // /// Sends a GET request of type `command` with query string `request`.
    // #[inline]
    // pub async fn get<T, R>(&self, command: &str, request: &T) -> Result<R, Error>
    // where
    //     T: Serialize,
    //     R: DeserializeOwned,
    // {
    //     self.request(Method::GET, command, request).await
    // }

    /// Sends a POST request of type `command` with query string `request`.
    #[inline]
    pub async fn post<T, R>(&self, command: &str, request: &T) -> Result<R, Error>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        self.request(Method::POST, command, request).await
    }
}
