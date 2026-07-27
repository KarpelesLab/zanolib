//! A blocking broadcast-and-collect helper over tsslib's message broker.

use crate::error::{Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::{Arc, Condvar, Mutex};
use tsslib::tss::{BrokerResult, JsonMessage, MessageReceiver, Parameters, json_get, json_wrap};

/// Collects one message per expected sender, waking a waiter when complete.
struct Collector {
    typ: String,
    from: Vec<tsslib::tss::PartyId>,
    state: Mutex<Vec<Option<JsonMessage>>>,
    done: Condvar,
}

impl MessageReceiver for Collector {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        if msg.typ != self.typ {
            return Err(format!(
                "unexpected message type {} while expecting {}",
                msg.typ, self.typ
            )
            .into());
        }
        let from = msg
            .from
            .as_ref()
            .ok_or_else(|| "message has no sender".to_string())?;
        let idx = self
            .from
            .iter()
            .position(|p| p.cmp_key(from) == std::cmp::Ordering::Equal)
            .ok_or_else(|| "message from an unexpected sender".to_string())?;

        let mut st = self.state.lock().expect("collector mutex");
        if st[idx].is_none() {
            st[idx] = Some(msg.clone());
            if st.iter().all(|s| s.is_some()) {
                self.done.notify_all();
            }
        }
        Ok(())
    }
}

/// Broadcasts `mine` as a `typ` message and blocks until every other party's
/// `typ` message has arrived.
///
/// Returns one value per party, indexed the same way as
/// [`Parameters::parties`] — this party's own entry is `mine`.
pub fn exchange<T>(params: &Parameters, typ: &str, mine: &T) -> Result<Vec<T>>
where
    T: Serialize + DeserializeOwned + Clone,
{
    let others = params.other_parties();
    let n = params.party_count();

    if others.is_empty() {
        return Ok(vec![mine.clone()]);
    }

    let collector = Arc::new(Collector {
        typ: typ.to_string(),
        from: others.clone(),
        state: Mutex::new(vec![None; others.len()]),
        done: Condvar::new(),
    });
    params.broker().connect(typ, collector.clone());

    let msg = json_wrap(typ, mine, Some(params.party_id().clone()), None)
        .map_err(|e| crate::err!("zanompc: encoding {typ}: {e}"))?;
    params
        .broker()
        .receive(&msg)
        .map_err(|e| crate::err!("zanompc: broker delivery failed: {e}"))?;

    let collected = {
        let mut st = collector.state.lock().expect("collector mutex");
        while st.iter().any(|s| s.is_none()) {
            st = collector.done.wait(st).expect("collector condvar");
        }
        st.clone()
    };

    // Index the results by the party's position in the sorted set.
    let mut out: Vec<Option<T>> = (0..n).map(|_| None).collect();
    out[params.party_index()] = Some(mine.clone());
    for (k, slot) in collected.into_iter().enumerate() {
        let msg = slot.expect("collector completed");
        let idx = params
            .parties()
            .iter()
            .position(|p| p.cmp_key(&others[k]) == std::cmp::Ordering::Equal)
            .ok_or_else(|| Error::msg("zanompc: sender is not a member of the party set"))?;
        out[idx] = Some(json_get(&msg).map_err(|e| crate::err!("zanompc: decoding {typ}: {e}"))?);
    }
    out.into_iter()
        .enumerate()
        .map(|(i, v)| v.ok_or_else(|| crate::err!("zanompc: missing {typ} message for party {i}")))
        .collect()
}
