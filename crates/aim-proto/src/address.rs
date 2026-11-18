//! Agent identities and recipient selectors.
//!
//! An agent is `host:harness:session`, e.g. `host-a:agy:s1`. The host
//! part is never chosen by the client: the hub derives it from the key that
//! authenticated the request. Clients name themselves as `harness:session`.

use std::fmt;

use crate::names::check_name;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgentId {
    pub host: String,
    pub harness: String,
    pub session: String,
}

impl AgentId {
    /// Splits and validates the client-side `harness:session` form.
    pub fn parse_local(local: &str) -> Result<(&str, &str), String> {
        let (harness, session) = local
            .split_once(':')
            .ok_or("agent must be HARNESS:SESSION, e.g. agy:s1 or codex:s2")?;
        check_name("agent harness", harness)?;
        check_name("agent session", session)?;
        Ok((harness, session))
    }

    /// Parses the client-side `harness:session` form and binds it to `host`.
    pub fn from_local(host: &str, local: &str) -> Result<Self, String> {
        let (harness, session) = Self::parse_local(local)?;
        check_name("host", host)?;
        Ok(Self {
            host: host.into(),
            harness: harness.into(),
            session: session.into(),
        })
    }

    /// Parses the full `host:harness:session` form.
    pub fn parse_full(text: &str) -> Result<Self, String> {
        let mut parts = text.split(':');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(host), Some(harness), Some(session), None) => {
                check_name("host", host)?;
                check_name("harness", harness)?;
                check_name("session", session)?;
                Ok(Self {
                    host: host.into(),
                    harness: harness.into(),
                    session: session.into(),
                })
            }
            _ => Err("agent id must be HOST:HARNESS:SESSION".into()),
        }
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.host, self.harness, self.session)
    }
}

/// Who a message is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// `*`: every agent on every computer.
    All,
    /// `host:NAME`: every agent on one computer.
    Host(String),
    /// `harness:NAME`: every agent of one kind (agy, codex, claude, ...).
    Harness(String),
    /// `repo:NAME`: every agent registered on that repository.
    Repo(String),
    /// `cap:NAME`: every agent advertising that capability.
    Cap(String),
    /// `HOST:HARNESS:SESSION`: exactly one agent.
    Agent(AgentId),
    /// `SESSION`: the agent with this session id, on any computer.
    Session(String),
}

impl Selector {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text == "*" {
            return Ok(Self::All);
        }
        let parts: Vec<&str> = text.split(':').collect();
        match parts.as_slice() {
            [session] => {
                check_name("recipient session", session)?;
                Ok(Self::Session((*session).into()))
            }
            [kind, name] => {
                check_name("recipient name", name)?;
                let name = (*name).to_string();
                match *kind {
                    "host" => Ok(Self::Host(name)),
                    "harness" => Ok(Self::Harness(name)),
                    "repo" => Ok(Self::Repo(name)),
                    "cap" => Ok(Self::Cap(name)),
                    _ => Err(format!(
                        "unknown recipient kind '{kind}': use *, host:NAME, harness:NAME, repo:NAME, cap:NAME, SESSION or HOST:HARNESS:SESSION"
                    )),
                }
            }
            [_, _, _] => AgentId::parse_full(text).map(Self::Agent),
            _ => Err(format!("invalid recipient '{text}'")),
        }
    }

    pub fn is_direct_match(&self, recipient: &AgentId) -> bool {
        match self {
            Self::Agent(id) => id == recipient,
            Self::Session(session) => *session == recipient.session,
            _ => false,
        }
    }

    pub fn matches(&self, recipient: &Recipient<'_>) -> bool {
        match self {
            Self::All => true,
            Self::Host(host) => *host == recipient.id.host,
            Self::Harness(harness) => *harness == recipient.id.harness,
            Self::Repo(repo) => recipient.repo == Some(repo.as_str()),
            Self::Cap(cap) => recipient.caps.iter().any(|c| c == cap),
            Self::Agent(id) => id == recipient.id,
            Self::Session(session) => *session == recipient.id.session,
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Host(n) => write!(f, "host:{n}"),
            Self::Harness(n) => write!(f, "harness:{n}"),
            Self::Repo(n) => write!(f, "repo:{n}"),
            Self::Cap(n) => write!(f, "cap:{n}"),
            Self::Agent(id) => write!(f, "{id}"),
            Self::Session(s) => f.write_str(s),
        }
    }
}

/// What the hub knows about a reading agent when matching selectors.
pub struct Recipient<'a> {
    pub id: &'a AgentId,
    pub repo: Option<&'a str>,
    pub caps: &'a [String],
}

/// Decides whether a message from `sender` addressed to `selectors` should be
/// delivered to `recipient`. Broadcasts/group selectors skip the sender itself
/// unless `include_self` is true or `recipient` was named directly.
pub fn deliverable(
    selectors: &[Selector],
    sender: &AgentId,
    recipient: &Recipient<'_>,
    include_self: bool,
) -> bool {
    if !selectors.iter().any(|s| s.matches(recipient)) {
        return false;
    }
    if sender == recipient.id && !include_self {
        return selectors.iter().any(|s| s.is_direct_match(recipient.id));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> AgentId {
        AgentId::parse_full(text).unwrap()
    }

    #[test]
    fn local_ids_bind_to_the_key_host() {
        let agent = AgentId::from_local("host-b", "codex:s1").unwrap();
        assert_eq!(agent.to_string(), "host-b:codex:s1");
        assert!(AgentId::from_local("host-b", "codex").is_err());
        assert!(AgentId::from_local("host-b", "codex:a:b").is_err());
        assert!(AgentId::from_local("host-b", ":x").is_err());
    }

    #[test]
    fn selectors_round_trip() {
        for text in [
            "*",
            "host:host-b",
            "harness:agy",
            "repo:example-repo",
            "cap:macos-gui",
            "host-b:agy:s1",
            "s1",
        ] {
            assert_eq!(Selector::parse(text).unwrap().to_string(), text);
        }
        for bad in ["", "planet:mars", "a:b:c:d", "host:", "host:a b"] {
            assert!(Selector::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn matching() {
        let me = id("host-a:agy:s1");
        let caps = vec!["linux-gui".to_string()];
        let r = Recipient {
            id: &me,
            repo: Some("example-repo"),
            caps: &caps,
        };
        let yes = [
            "*",
            "host:host-a",
            "harness:agy",
            "repo:example-repo",
            "cap:linux-gui",
            "host-a:agy:s1",
            "s1",
        ];
        for text in yes {
            assert!(Selector::parse(text).unwrap().matches(&r), "{text}");
        }
        let no = [
            "host:host-b",
            "harness:codex",
            "repo:other-repo",
            "cap:macos-gui",
            "host-b:agy:s1",
            "s2",
        ];
        for text in no {
            assert!(!Selector::parse(text).unwrap().matches(&r), "{text}");
        }
        let unregistered = Recipient {
            id: &me,
            repo: None,
            caps: &[],
        };
        assert!(!Selector::parse("repo:example-repo")
            .unwrap()
            .matches(&unregistered));

        let other = id("host-b:codex:s2");
        let broadcast = vec![Selector::All];
        assert!(!deliverable(&broadcast, &me, &r, false));
        assert!(deliverable(&broadcast, &me, &r, true));
        assert!(deliverable(&broadcast, &other, &r, false));

        let direct = vec![Selector::Agent(me.clone())];
        assert!(deliverable(&direct, &me, &r, false));
    }
}
