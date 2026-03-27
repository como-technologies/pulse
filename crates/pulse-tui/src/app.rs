use pulse_client::{
    PulseClient, ReadyToken, ReqwestTransport, SessionContext, current_epoch, derive_pseudonym,
    encrypt_response, generate_employee_secret,
};
use pulse_crypto::BrssPublicKey;
use pulse_protocol::messages::{QuestionDelivery, ResponseData, ResponseType};
use pulse_protocol::token::AttestationClass;
use pulse_protocol::{KeyVersion, TenantId};
use tokio::sync::mpsc;

use crate::action::Action;

/// Which screen the user is on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Connect,
    Login,
    Questions,
    Token,
    Respond,
    Submit,
}

/// Which field is focused on the Connect screen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnectField {
    IdentityUrl,
    SignalUrl,
}

/// Application state — the "Model" in the Elm architecture.
pub struct App {
    pub screen: Screen,
    pub should_quit: bool,

    // Connect screen
    pub identity_url: String,
    pub signal_url: String,
    pub connect_field: ConnectField,

    // Login screen
    pub api_key: String,
    pub login_status: Option<String>,

    // Session + server config (populated after connect+auth)
    pub session: Option<SessionContext>,
    pub tenant_id: Option<TenantId>,
    pub key_version: Option<KeyVersion>,
    pub public_key: Option<BrssPublicKey>,

    // Questions screen
    pub questions: Vec<QuestionDelivery>,
    pub selected_question: usize,

    // Token screen
    pub token_status: String,
    pub ready_token: Option<Box<ReadyToken>>,

    // Respond screen
    pub scale_value: u8,
    pub text_response: String,

    // Submit screen
    pub submit_status: String,

    // Protocol log
    pub log: Vec<String>,

    // Async channel for protocol results
    pub protocol_tx: mpsc::UnboundedSender<Action>,

    // Analytics DEK (not yet distributed via protocol — generated locally for now)
    pub analytics_dek: Option<[u8; 32]>,
}

impl App {
    pub fn new(protocol_tx: mpsc::UnboundedSender<Action>) -> Self {
        Self {
            screen: Screen::Connect,
            should_quit: false,
            identity_url: "http://127.0.0.1:8001".to_string(),
            signal_url: "http://127.0.0.1:8002".to_string(),
            connect_field: ConnectField::IdentityUrl,
            api_key: String::new(),
            login_status: None,
            session: None,
            tenant_id: None,
            key_version: None,
            public_key: None,
            questions: Vec::new(),
            selected_question: 0,
            token_status: String::new(),
            ready_token: None,
            scale_value: 3,
            text_response: String::new(),
            submit_status: String::new(),
            log: vec!["Welcome to Pulse TUI".to_string()],
            protocol_tx,
            analytics_dek: None,
        }
    }

    /// Process an action.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,

            Action::Back => match self.screen {
                Screen::Connect => self.should_quit = true,
                Screen::Login => self.screen = Screen::Connect,
                Screen::Questions => self.screen = Screen::Login,
                Screen::Token => self.screen = Screen::Questions,
                Screen::Respond => self.screen = Screen::Questions,
                Screen::Submit => {
                    self.screen = Screen::Questions;
                    self.ready_token = None;
                    self.submit_status.clear();
                }
            },

            Action::NextField | Action::PrevField => {
                if self.screen == Screen::Connect {
                    self.connect_field = match self.connect_field {
                        ConnectField::IdentityUrl => ConnectField::SignalUrl,
                        ConnectField::SignalUrl => ConnectField::IdentityUrl,
                    };
                }
            }

            Action::CharInput(c) => match self.screen {
                Screen::Connect => match self.connect_field {
                    ConnectField::IdentityUrl => self.identity_url.push(c),
                    ConnectField::SignalUrl => self.signal_url.push(c),
                },
                Screen::Login => self.api_key.push(c),
                Screen::Respond => self.text_response.push(c),
                _ => {}
            },

            Action::Backspace => match self.screen {
                Screen::Connect => match self.connect_field {
                    ConnectField::IdentityUrl => {
                        self.identity_url.pop();
                    }
                    ConnectField::SignalUrl => {
                        self.signal_url.pop();
                    }
                },
                Screen::Login => {
                    self.api_key.pop();
                }
                Screen::Respond => {
                    self.text_response.pop();
                }
                _ => {}
            },

            Action::SelectUp => match self.screen {
                Screen::Questions if self.selected_question > 0 => {
                    self.selected_question -= 1;
                }
                Screen::Respond if self.scale_value < 5 => {
                    self.scale_value += 1;
                }
                _ => {}
            },

            Action::SelectDown => match self.screen {
                Screen::Questions if self.selected_question + 1 < self.questions.len() => {
                    self.selected_question += 1;
                }
                Screen::Respond if self.scale_value > 1 => {
                    self.scale_value -= 1;
                }
                _ => {}
            },

            Action::ScaleUp => {
                if self.screen == Screen::Respond && self.scale_value < 5 {
                    self.scale_value += 1;
                }
            }

            Action::ScaleDown => {
                if self.screen == Screen::Respond && self.scale_value > 1 {
                    self.scale_value -= 1;
                }
            }

            Action::Submit => match self.screen {
                Screen::Connect => {
                    self.log.push(format!(
                        "Connecting: identity={}, signal={}",
                        self.identity_url, self.signal_url
                    ));
                    self.screen = Screen::Login;
                }
                Screen::Login => {
                    self.login_status = Some("Connecting...".to_string());
                    self.spawn_connect_and_auth();
                }
                Screen::Questions if !self.questions.is_empty() => {
                    self.screen = Screen::Token;
                    self.token_status = "Blinding token...".to_string();
                    self.spawn_token_flow();
                }
                Screen::Respond => {
                    self.screen = Screen::Submit;
                    self.submit_status = "Encrypting and submitting...".to_string();
                    self.spawn_submit();
                }
                _ => {}
            },

            Action::Connected {
                session,
                questions,
                tenant_id,
                key_version,
                public_key,
            } => {
                self.session = Some(session);
                self.tenant_id = Some(tenant_id);
                self.key_version = Some(key_version);
                self.public_key = Some(public_key);
                self.questions = questions;
                self.selected_question = 0;
                self.login_status = Some("Connected!".to_string());
                self.screen = Screen::Questions;
            }

            Action::TokenReady(token) => {
                self.token_status = "Token ready!".to_string();
                self.log.push(
                    "[Client] Signature unblinded and verified — token ready for submission"
                        .to_string(),
                );
                self.ready_token = Some(token);
                self.screen = Screen::Respond;
            }

            Action::ResponseSubmitted => {
                self.submit_status = "Response submitted successfully!".to_string();
                self.log.push(
                    "[Signal Zone] Response accepted — anonymous, verified, stored".to_string(),
                );
            }

            Action::ProtocolError(err) => {
                let msg = format!("Error: {err}");
                self.log.push(msg.clone());
                match self.screen {
                    Screen::Login => self.login_status = Some(msg),
                    Screen::Token => self.token_status = msg,
                    Screen::Submit => self.submit_status = msg,
                    _ => {}
                }
            }

            Action::Log(msg) => {
                self.log.push(msg);
            }
        }
    }

    fn spawn_connect_and_auth(&self) {
        let tx = self.protocol_tx.clone();
        let identity_url = self.identity_url.clone();
        let signal_url = self.signal_url.clone();
        let api_key = self.api_key.clone();

        tokio::spawn(async move {
            let mut client = PulseClient::new(ReqwestTransport::new(), identity_url, signal_url);

            // Step 1: Fetch server config (public key, tenant ID)
            let _ = tx.send(Action::Log(
                "[Identity Zone] GET /config (fetching public key + tenant)".to_string(),
            ));
            let config = match client.connect().await {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };
            let _ = tx.send(Action::Log(format!(
                "[Identity Zone] Config: tenant={}, key_version={}",
                config.tenant_id, config.key_version
            )));

            // Step 2: Authenticate
            let _ = tx.send(Action::Log("[Identity Zone] POST /auth".to_string()));
            let session = match client.authenticate(&api_key).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };
            let _ = tx.send(Action::Log("[Identity Zone] Authenticated".to_string()));

            // Step 3: Fetch questions
            let _ = tx.send(Action::Log("[Identity Zone] GET /question".to_string()));
            let questions = match client.fetch_questions(&session).await {
                Ok(q) => q,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };
            let _ = tx.send(Action::Log(format!(
                "[Identity Zone] Received {} question(s)",
                questions.len()
            )));

            let _ = tx.send(Action::Connected {
                session,
                questions,
                tenant_id: config.tenant_id,
                key_version: config.key_version,
                public_key: config.public_key,
            });
        });
    }

    fn spawn_token_flow(&mut self) {
        let tx = self.protocol_tx.clone();
        let identity_url = self.identity_url.clone();
        let session_token = self.session.as_ref().unwrap().session_token.clone();
        let question = self.questions[self.selected_question].clone();
        let pk = self.public_key.clone().unwrap();
        let tenant_id = self.tenant_id.unwrap();
        let key_version = self.key_version.unwrap();

        tokio::spawn(async move {
            let client = PulseClient::with_config(
                ReqwestTransport::new(),
                identity_url,
                String::new(),
                pk,
                tenant_id,
                key_version,
            );

            let session = pulse_client::SessionContext { session_token };

            let _ = tx.send(Action::Log(
                "[Client] Blinding token with random factor...".to_string(),
            ));

            let blinded = match client.blind_token(&question, AttestationClass::Personal) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };

            let _ = tx.send(Action::Log(
                "[Identity Zone] POST /token/sign (blinded — server cannot see contents)"
                    .to_string(),
            ));

            let signed = match client.request_signature(&session, blinded).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };

            let _ = tx.send(Action::Log("[Client] Unblinding signature...".to_string()));

            match client.finalize_token(signed) {
                Ok(ready) => {
                    let _ = tx.send(Action::TokenReady(Box::new(ready)));
                }
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                }
            }
        });
    }

    fn spawn_submit(&mut self) {
        let tx = self.protocol_tx.clone();
        let signal_url = self.signal_url.clone();
        let ready_token = self.ready_token.take().unwrap();
        let tenant_id = self.tenant_id.unwrap();

        let question = &self.questions[self.selected_question];
        let response_type = question.response_type.clone();
        let segment_vector = ready_token.token_payload().segment_vector.clone();

        let response_data = match response_type {
            ResponseType::Scale5 => ResponseData::Scale5(self.scale_value),
            ResponseType::Binary => ResponseData::Binary(self.scale_value > 2),
            ResponseType::FreeText => ResponseData::FreeText(self.text_response.clone()),
            ResponseType::Emoji => ResponseData::Emoji(self.text_response.clone()),
        };

        let analytics_dek = self.analytics_dek;

        tokio::spawn(async move {
            let _ = tx.send(Action::Log(
                "[Client] Deriving anonymous pseudonym (HMAC-SHA256)...".to_string(),
            ));

            let employee_secret = generate_employee_secret();
            let epoch_id = current_epoch();
            let pseudonym = derive_pseudonym(&employee_secret, &tenant_id, &epoch_id);

            let _ = tx.send(Action::Log(
                "[Client] Encrypting response payload (AES-256-GCM)...".to_string(),
            ));

            let dek = analytics_dek.unwrap_or_else(pulse_crypto::aead::generate_key);

            let blob = match encrypt_response(
                &dek,
                pseudonym,
                epoch_id,
                response_type,
                response_data,
                segment_vector,
            ) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                    return;
                }
            };

            let _ = tx.send(Action::Log(
                "[Signal Zone] POST /response (anonymous — NO auth, NO identity)".to_string(),
            ));

            let submit = ready_token.build_submission(blob);
            let body = match postcard::to_allocvec(&submit) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(
                        pulse_client::ClientError::Serialization(e.to_string()),
                    ));
                    return;
                }
            };

            let transport = ReqwestTransport::new();
            use pulse_client::HttpTransport;
            match transport
                .post_binary(&format!("{signal_url}/response"), &body, None)
                .await
            {
                Ok(r) if r.status == 200 => {
                    let _ = tx.send(Action::ResponseSubmitted);
                }
                Ok(r) if r.status == 422 => {
                    let body = String::from_utf8_lossy(&r.body).into_owned();
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        let _ = tx.send(Action::ProtocolError(
                            pulse_client::ClientError::ResponseRejected {
                                code: json["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                                reason: json["message"].as_str().unwrap_or("unknown").to_string(),
                            },
                        ));
                    } else {
                        let _ = tx.send(Action::ProtocolError(
                            pulse_client::ClientError::ServerError {
                                status: r.status,
                                body,
                            },
                        ));
                    }
                }
                Ok(r) => {
                    let body = String::from_utf8_lossy(&r.body).into_owned();
                    let _ = tx.send(Action::ProtocolError(
                        pulse_client::ClientError::ServerError {
                            status: r.status,
                            body,
                        },
                    ));
                }
                Err(e) => {
                    let _ = tx.send(Action::ProtocolError(e));
                }
            }
        });
    }
}
