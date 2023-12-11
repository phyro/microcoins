# Don't trust me with cryptography.

"""
System design was motivated by MR01 as described in the Micropayments revisited paper [1].

It does not exactly follow the paper implementation which can cause additional mistakes. We changed some of the
terminology and refer to a check as a `transaction` and an account on the bank, regardless whether it's a user
or a merchant as a `wallet`. This is adopted from the blockchain terminology.

[1] https://people.csail.mit.edu/rivest/pubs/MR02a.prepub.pdf
"""


import binascii
import hashlib
import os
import time

import vrf.vrf as vrf


MP = 10  # How many coins is considered a macro payment


def H(_input):
    """Hash function used to generate pseudorandom data."""
    _input = str(_input)
    return hashlib.sha256(_input.encode("utf-8")).hexdigest()


class ErrUnknownSender(Exception):
    pass


class ErrInvalidCoinInterval(Exception):
    pass


class ErrNotPayable(Exception):
    pass


class ErrNotEnoughFunds(Exception):
    pass


class ErrAlreadyProcessed(Exception):
    pass


class ErrDoubleSpend(Exception):
    pass


class Transaction:
    """
    A transaction is a check. The serial number `sn` is defiend as `sn_prev + amount`.
    This means the serial number interval is [sn-amount + 1, sn].

    e.g.
    The last coin we used was the serial number 3. We now send a payment with amount being 4 and sn being 7.
    This means the range the transaction describes is [7-4+1, 7] => [4, 7] which represents [4, 5, 6, 7].
    """

    def __init__(self, sn, amount, sender_key, receiver_key, timestamp):
        self.sn = sn
        self.amount = amount
        self.sender_key = sender_key
        self.receiver_key = receiver_key
        self.timestamp = str(int(timestamp))

        assert sn > 0  # serial number can't be negative
        assert amount > 0  # negative amounts are not allowed
        assert (
            sn >= amount
        )  # serial number interval has to be 'amount' length and positive

    def __eq__(self, other):
        return (
            self.sn == other.sn
            and self.amount == other.amount
            and self.sender_key == other.sender_key
            and self.receiver_key == other.receiver_key
            and self.timestamp == other.timestamp
        )

    @property
    def msg(self):
        """Returns the message to sign."""
        return H(
            ";".join(
                [
                    "sn=" + str(self.sn),  # sender's card serial number
                    "amt=" + str(self.amount),  # amount paid
                    "r=" + self.receiver_key,  # receiver key
                    "t=" + self.timestamp,  # transaction timestamp
                ]
            )
        )

    @staticmethod
    def calculate_payment(MP, amount, attempt_hex):
        """Given the MP, amount and attempt_hex returns the payment value."""
        # We pay a MP for every MP coins and calculate the probability for the remainder
        amount_paid = (amount // MP) * MP
        remaining_amount = amount % MP

        prob = remaining_amount / float(MP)  # m/M is the probability
        difficulty_target = (2**512) * prob  # the range interval is [0, 2^512]
        if (
            int(attempt_hex, 16) < difficulty_target
        ):  # pay if it hit the difficulty target
            amount_paid += MP

        # NOTE: An alternative implementation would be to return amount if amount > MP, else calc probability.
        return amount_paid

    def evaluate(self, sender_sig, receiver_sig):
        """Verifies that the transaction is correctly signed and returns how much the transaction pays."""
        msg = self.msg
        # Sender signs the transaction message and produces vrf proof 'beta' (hash of pi)
        beta_sender = vrf.vrf_fullverify(self.sender_key.decode("hex"), sender_sig, msg)
        # Receiver signs the beta proof of the sender to produce receiver's beta
        beta_receiver = vrf.vrf_fullverify(
            self.receiver_key.decode("hex"), receiver_sig, beta_sender
        )
        hex_beta = beta_receiver.encode("hex")
        assert (
            len(hex_beta) == 128
        )  # vrf implementation uses sha512 so the hex length is 128

        return self.calculate_payment(MP, self.amount, hex_beta)


class Wallet:
    @classmethod
    def create(cls, amount):
        sk = os.urandom(32)
        hex_sk = binascii.hexlify(sk).decode()
        return cls(hex_sk, amount)

    def __init__(self, priv_key, amount):
        self.total_received = 0
        self.sn = 0
        self.priv_key = priv_key.decode("hex")
        self.amount = amount

    @property
    def pubkey(self):
        """Returns the wallet pubkey."""
        _, mypk = vrf.sk_to_privpub(self.priv_key)
        return vrf.ec2osp(mypk).encode("hex")

    def pay(self, receiver_key, amount, timestamp=None):
        """Pays 'amount' coins to the given receiver key."""
        assert isinstance(amount, int)
        if amount < 1:
            raise ValueError("Amount can't be less than 1.")
        if amount > self.amount:
            raise ValueError("Not enough balance.")
        if timestamp is None:
            timestamp = time.time()

        T = Transaction(self.sn + amount, amount, self.pubkey, receiver_key, timestamp)
        pi = sender_sig = vrf.vrf_prove(self.priv_key, T.msg)
        self.sn += amount
        self.amount -= amount  # Note: this is expected amount in this implementation
        return T, sender_sig

    def sign_receive(self, T, sender_sig):
        assert T.receiver_key == self.pubkey  # assert the payment is for me
        sender_beta = vrf.vrf_fullverify(
            T.sender_key.decode("hex"), sender_sig, T.msg
        )  # verify sender sig
        pi = receiver_sig = vrf.vrf_prove(self.priv_key, sender_beta)  # sign
        return T, receiver_sig


class Bank:
    def __init__(self):
        """
        users: {
            <pubkey>: {
                "total_received": <amount>,
                "balance": <amount>,
                "history": {
                    <sn>: (<tx>, <sender_sig>, <receiver_sig>),
                    ...
                }
            }
        }
        """
        self.users = dict()  # user balances and history

    def user_balance(self, user_key):
        if user_key not in self.users:
            return 0
        return self.users[user_key]["balance"]

    def ensure_user_exists(self, user_key):
        if user_key not in self.users:
            self.users[user_key] = {
                "total_received": 0,
                "balance": 0,
                "history": dict(),
            }

    def find_shared_sn_subrange(self, tx):
        """Returns the first transaction that was published and shared the subrange with the given transaction."""
        for user_tx, _, _ in self.users[tx.sender_key]["history"].values():
            if self.intersection_exists(tx, user_tx):
                return user_tx

        return None

    @staticmethod
    def intersection_exists(tx1, tx2):
        """Returns True if intersection exists, else False."""
        interval1 = (tx1.sn - tx1.amount + 1, tx1.sn)
        interval2 = (tx2.sn - tx2.amount + 1, tx2.sn)
        fst, snd = (
            (interval1, interval2)
            if interval1[0] <= interval2[0]
            else (interval2, interval1)
        )

        # p1 <= p2 <= p3
        return fst[0] <= snd[0] <= fst[1]

    def subtract_balance(self, tx, amount_paid, sender_sig, receiver_sig):
        """Updates the balance and history of the sender."""
        self.users[tx.sender_key]["balance"] -= amount_paid
        # Add transaction entry to history
        self.users[tx.sender_key]["history"][tx.sn] = (tx, sender_sig, receiver_sig)

    def add_balance(self, user_key, amount):
        self.ensure_user_exists(user_key)
        # either MP or the amount if its higher than MP
        self.users[user_key]["balance"] += amount
        # increase the total in-value
        self.users[user_key]["total_received"] += amount

    def verify_payable(self, tx, sender_sig, receiver_sig):
        amount_paid = tx.evaluate(sender_sig, receiver_sig)
        if amount_paid == 0:
            raise ErrNotPayable

        return amount_paid

    def validate_payment(self, tx, sender_sig, receiver_sig):
        amount_paid = self.verify_payable(tx, sender_sig, receiver_sig)
        # Ensure the sender exists in the database
        if tx.sender_key not in self.users:
            raise ErrUnknownSender

        intersect_tx = self.find_shared_sn_subrange(tx)
        if intersect_tx:
            # We know the sigs of `tx` were processed in `verify_payable` and the intersect_tx was verified when it
            # got inserted in our database. If the two are not the same, the sender signed the same subrange twice.
            if tx == intersect_tx:
                raise ErrAlreadyProcessed
            # The sender made two different transactions with the same serial number
            raise ErrDoubleSpend

        # Validate the coins the sender used are in range (0, total_received). Anything outside is invalid.
        if tx.sn - tx.amount < 0 or tx.sn > self.users[tx.sender_key]["total_received"]:
            # This can be handled in many ways including punishment
            raise ErrInvalidCoinInterval
        # Check if the sender has enough funds to pay for transaction
        if self.users[tx.sender_key]["balance"] < amount_paid:
            raise ErrNotEnoughFunds

        return amount_paid

    def process_payment(self, tx, sender_sig, receiver_sig):
        amount_paid = self.validate_payment(tx, sender_sig, receiver_sig)
        self.subtract_balance(tx, amount_paid, sender_sig, receiver_sig)
        self.add_balance(tx.receiver_key, amount_paid)

        return True

    def report_double_spend(
        self, tx1, sender_sig1, receiver_sig1, tx2, sender_sig2, receiver_sig2
    ):
        """A double-spend can be reported by a user by revealing a nonpayable transaction with shared sn subrange.
        Note that payable transaction double-spends are caught by the `process_payment` function.
        """
        # Make sure both transactions are correctly signed
        _ = tx1.evaluate(sender_sig1, receiver_sig1)
        _ = tx2.evaluate(sender_sig2, receiver_sig2)

        # Raise a double-spend error if the sender signed the same coin interval on different transactions
        if (
            tx1 != tx2
            and tx1.sender_key == tx2.sender_key
            and self.intersection_exists(tx1, tx2)
        ):
            # A more serious implementation would have consequences
            raise ErrDoubleSpend

        return None

    def deposit(self, user_key, amount):
        """Assumes the user deposited some cash to get the coins. This just bumps the balance."""
        self.add_balance(user_key, amount)
