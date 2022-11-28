use std::{cell::RefCell, collections::HashMap, rc::Rc};

use encryption::account::{AccountConnection, AmbiguousAccount, ImplicitAccount, ID};

use crate::messages::{IncomingMessage, MessagePayload, OutgoingMessage};

pub struct ChatPool {
    account: ImplicitAccount,
    chats: HashMap<ID, Rc<RefCell<Chat>>>,
}

impl ChatPool {
    pub fn new(account: ImplicitAccount) -> Self {
        Self {
            account: account,
            chats: HashMap::new(),
        }
    }

    pub fn get_chat(&mut self, with: AmbiguousAccount) -> Rc<RefCell<Chat>> {
        let account = self.account.clone();

        Rc::clone(self.chats.entry(with.id.clone()).or_insert_with(move || {
            Rc::new(RefCell::new(Chat {
                with: with.clone(),
                messages: Vec::new(),
                secret: AccountConnection::from_accounts(&account, &with).secret,
                on_message: |message: MessagePayload| {
                    println!(
                        "{:?} -> {:?}",
                        IncomingMessage::from_payload(message.clone()),
                        message.contents,
                    )
                },
            }))
        }))
    }
}

pub struct Chat {
    with: AmbiguousAccount,
    messages: Vec<MessagePayload>,
    secret: Vec<u8>,
    on_message: fn(MessagePayload),
}

impl Chat {
    pub fn send_message(&mut self, message: OutgoingMessage) {
        println!("{:?}", self.secret);
        (self.on_message)(message.to_payload(&self.secret[0..16].to_vec()));
    }
}
