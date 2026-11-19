//! Message types (speech acts) and the reply rules between them.
//!
//! Typing the intent of a message, instead of leaving it to free text, is what
//! keeps agents out of acknowledgement loops: `ANNOUNCE` and `RESULT` never ask
//! for an answer, and nobody may "reply" to a `RESULT` at all.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Performative {
    /// Status for everyone: pushed a branch, PR ready, merged. No answer expected.
    Announce,
    /// A question to someone. Answered by `REPLY`.
    Query,
    /// The answer to a `QUERY`.
    Reply,
    /// Ask another agent to do something (a task, build, deploy).
    Request,
    /// Ask another agent to verify something it can run and you cannot
    /// (another OS, GPU, GUI, hardware).
    RequestVerify,
    /// "I am taking this request." Only one agent can accept a request.
    Accept,
    /// "I will not / cannot take this."
    Reject,
    /// Still working on an accepted request.
    Progress,
    /// The final outcome of a request. Ends it; nobody replies to a result.
    Result,
    /// Sender withdraws an open request or query.
    Cancel,
    /// Something others should know about now (disk floor, runner offline).
    Alert,
    /// Work is stuck and needs someone.
    Blocker,
    /// My work overlaps with yours.
    Conflict,
}

use Performative::*;

impl Performative {
    pub const ALL: [Performative; 13] = [
        Announce,
        Query,
        Reply,
        Request,
        RequestVerify,
        Accept,
        Reject,
        Progress,
        Result,
        Cancel,
        Alert,
        Blocker,
        Conflict,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Announce => "ANNOUNCE",
            Query => "QUERY",
            Reply => "REPLY",
            Request => "REQUEST",
            RequestVerify => "REQUEST_VERIFY",
            Accept => "ACCEPT",
            Reject => "REJECT",
            Progress => "PROGRESS",
            Result => "RESULT",
            Cancel => "CANCEL",
            Alert => "ALERT",
            Blocker => "BLOCKER",
            Conflict => "CONFLICT",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        let upper = text.trim().to_ascii_uppercase().replace('-', "_");
        Self::ALL.into_iter().find(|p| p.as_str() == upper)
    }

    /// A request someone can accept and must finish with a `RESULT`.
    pub fn is_request(self) -> bool {
        matches!(self, Request | RequestVerify)
    }

    /// May start a new thread (be sent without `reply_to`).
    pub fn may_start_thread(self) -> bool {
        matches!(
            self,
            Announce | Query | Request | RequestVerify | Alert | Blocker | Conflict
        )
    }

    /// May `self` be sent as a reply to a message of type `parent`?
    pub fn may_reply_to(self, parent: Performative) -> bool {
        let allowed: &[Performative] = match parent {
            Query => &[Reply, Reject, Query, Cancel],
            Request | RequestVerify => &[Accept, Reject, Progress, Result, Query, Cancel],
            Announce => &[Conflict, Blocker, Query],
            Reply => &[Query, Request, RequestVerify],
            Accept | Progress => &[Query, Blocker],
            Reject => &[Query, Request, RequestVerify],
            // Results and cancellations are terminal: only a new request may follow.
            Result | Cancel => &[Request, RequestVerify],
            Alert | Blocker => &[Reply, Progress, Result, Query],
            Conflict => &[Reply, Query],
        };
        allowed.contains(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_lenient_about_case_and_dashes() {
        assert_eq!(Performative::parse("request-verify"), Some(RequestVerify));
        assert_eq!(Performative::parse(" Result "), Some(Result));
        assert_eq!(Performative::parse("ack"), None);
        for p in Performative::ALL {
            assert_eq!(Performative::parse(p.as_str()), Some(p));
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
        }
    }

    #[test]
    fn results_and_cancellations_are_terminal() {
        for p in Performative::ALL {
            assert_eq!(p.may_reply_to(Result), p.is_request(), "{p:?} after RESULT");
            assert_eq!(p.may_reply_to(Cancel), p.is_request(), "{p:?} after CANCEL");
        }
    }

    #[test]
    fn queries_allow_follow_up_and_cancel() {
        assert!(Query.may_reply_to(Query));
        assert!(Cancel.may_reply_to(Query));
        assert!(Cancel.may_reply_to(Request));
        assert!(Cancel.may_reply_to(RequestVerify));
        assert!(!Cancel.may_reply_to(Announce));
        assert!(!Cancel.may_reply_to(Reply));
    }

    #[test]
    fn no_acknowledgement_loops() {
        // Nothing answers an ANNOUNCE with a plain REPLY ("ack"), and a REPLY
        // cannot be answered with another REPLY.
        assert!(!Reply.may_reply_to(Announce));
        assert!(!Reply.may_reply_to(Reply));
        assert!(!Reply.may_reply_to(Cancel));
        assert!(!Announce.may_reply_to(Announce));
        assert!(!Announce.may_reply_to(Result));
        assert!(!Announce.may_reply_to(Cancel));
    }

    #[test]
    fn replies_cannot_start_threads() {
        for p in [Reply, Accept, Reject, Progress, Result, Cancel] {
            assert!(!p.may_start_thread(), "{p:?}");
        }
    }
}
