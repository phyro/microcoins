# Don't trust me with cryptography.

import unittest

from mr01 import (
    Bank,
    Wallet,
    Transaction,
    ErrAlreadyProcessed,
    ErrDoubleSpend,
    ErrInvalidCoinInterval,
    ErrNotPayable,
    ErrNotEnoughFunds,
)


class TestMR01(unittest.TestCase):
    def setUp(self):
        self.MP = 10

        # Values for a transaction where 1 coin that is paid to the receiver wins the macro payment
        timestamp = 1700009006
        card1 = Wallet(
            "c8574aa78691e450adb1a002e7febc2620100e7bc41891a497b6fff0e7c44445",
            0,
        )
        card2 = Wallet(
            "a326d26c5a26279a3126ca6ddb644cf2c91277e76f88268244393cb8aa0436ea",
            0,
        )

        # Cases for transactions that hit and miss a macro payment
        self.cases = {
            # inner structure: <amount>: (U1, U2, timestamp)
            "hit": {
                "1": (card1, card2, timestamp),
            },
            "miss": {"1": (card1, card2, timestamp + 1)},
        }

    def test_deposit(self):
        B = Bank()
        my_card = Wallet.create(0)

        self.assertEqual(B.user_balance(my_card.pubkey), 0)
        B.deposit(my_card.pubkey, 15)
        self.assertEqual(B.user_balance(my_card.pubkey), 15)

    def test_happy_path(self):
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        T, sender_sig = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T, receiver_sig = card2.sign_receive(T, sender_sig)

        self.assertEqual(B.user_balance(T.sender_key), 15)
        self.assertEqual(B.user_balance(T.receiver_key), 0)

        self.assertEqual(T.evaluate(sender_sig, receiver_sig), self.MP)
        self.assertTrue(B.process_payment(T, sender_sig, receiver_sig))

        self.assertEqual(B.user_balance(T.sender_key), 5)
        self.assertEqual(B.user_balance(T.receiver_key), 10)

    def test_not_payable(self):
        B = Bank()
        (card1, card2, timestamp) = self.cases["miss"]["1"]
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        T, sender_sig = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T, receiver_sig = card2.sign_receive(T, sender_sig)

        self.assertEqual(T.evaluate(sender_sig, receiver_sig), 0)
        with self.assertRaises(ErrNotPayable):
            B.process_payment(T, sender_sig, receiver_sig)

    def test_already_processed(self):
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        T, sender_sig = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T, receiver_sig = card2.sign_receive(T, sender_sig)

        self.assertEqual(T.evaluate(sender_sig, receiver_sig), self.MP)
        self.assertTrue(B.process_payment(T, sender_sig, receiver_sig))

        # Construct a new transaction object and try to process it again
        T2 = Transaction(T.sn, 1, T.sender_key, T.receiver_key, int(T.timestamp))
        self.assertNotEqual(
            id(T), id(T2)
        )  # make sure we're not comparing object pointers

        with self.assertRaises(ErrAlreadyProcessed):
            self.assertEqual(T.evaluate(sender_sig, receiver_sig), self.MP)
            B.process_payment(T, sender_sig, receiver_sig)

    def test_amount_over_MP_hit(self):
        """Tests a case where amount > MP. It should pay multiple MP values and decide the remained probabilistically.
        This tests the case where the remained probability is a 'hit' meaning it pays MP too.
        """
        B = Bank()
        # Hardcoded values to produce a payable transaction that also wins 3/10 probability MP
        timestamp = 1700009006
        card1 = Wallet(
            "94288b57381f7cf9893ccec70932f625538e4c96c5227bc4e133ce2af4334ef9",
            0,
        )
        card2 = Wallet(
            "b230360f26b3bd515cc9c39a6ff9f203677f2974c80d4e35a416963ebf45867d",
            0,
        )
        B.deposit(card1.pubkey, 21)
        card1.amount = 21

        T, sender_sig = card1.pay(card2.pubkey, 13, timestamp)
        self.assertEqual(card1.amount, 8)
        T, receiver_sig = card2.sign_receive(T, sender_sig)

        # we get 1*MP because the payment went over MP and we get a hit with 3/10 probability to receive another MP
        self.assertEqual(T.evaluate(sender_sig, receiver_sig), 2 * self.MP)
        self.assertTrue(B.process_payment(T, sender_sig, receiver_sig))
        self.assertEqual(
            B.user_balance(T.sender_key), 1
        )  # our card has incorrect balance atm. Gets averaged out over time.
        self.assertEqual(B.user_balance(T.receiver_key), 2 * self.MP)

    def test_amount_over_MP_miss(self):
        """Tests a case where amount > MP. It should pay multiple MP values and decide the remained probabilistically.
        This tests the case where the remained probability is a 'miss' meaning it doesn't pay MP.
        """
        B = Bank()
        # Hardcoded values to produce a payable transaction that doesn't win 3/10 probability MP
        timestamp = 1700009007
        card1 = Wallet(
            "94288b57381f7cf9893ccec70932f625538e4c96c5227bc4e133ce2af4334ef9",
            0,
        )
        card2 = Wallet(
            "b230360f26b3bd515cc9c39a6ff9f203677f2974c80d4e35a416963ebf45867d",
            0,
        )
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        T, sender_sig = card1.pay(card2.pubkey, 13, timestamp)
        self.assertEqual(card1.amount, 2)
        T, receiver_sig = card2.sign_receive(T, sender_sig)

        # we get 1*MP because the payment went over MP and we got a hit with 3/10 probability
        self.assertEqual(T.evaluate(sender_sig, receiver_sig), 1 * self.MP)
        self.assertTrue(B.process_payment(T, sender_sig, receiver_sig))

    def test_double_spend_report(self):
        """Tests a double spend reported by a user."""
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        # T1: Card1 SN=1 => Card2
        T1, sender_sig1 = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T1, receiver_sig1 = card2.sign_receive(T1, sender_sig1)

        self.assertEqual(T1.evaluate(sender_sig1, receiver_sig1), self.MP)
        self.assertTrue(B.process_payment(T1, sender_sig1, receiver_sig1))

        # Automatically reset sn and amount values on the card
        card1.sn = 0
        card1.amount = 15
        card3 = Wallet.create(0)

        # NOTE: It doesn't matter if it's a hiss or a miss. We report it before it's processed.
        # T2: Card1 SN=1 => Card3 (double-spend)
        T2, sender_sig2 = card1.pay(card3.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T2, receiver_sig2 = card3.sign_receive(T2, sender_sig2)

        # T3: Card1 SN=2 => Card2 (valid)
        T3, sender_sig3 = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 13)
        T3, receiver_sig3 = card2.sign_receive(T3, sender_sig3)

        # Test positive report case
        with self.assertRaises(ErrDoubleSpend):
            B.report_double_spend(
                T1, sender_sig1, receiver_sig1, T2, sender_sig2, receiver_sig2
            )

        # Test negative report case
        self.assertIsNone(
            B.report_double_spend(
                T1, sender_sig1, receiver_sig1, T3, sender_sig3, receiver_sig3
            )
        )

    def test_double_spend_process(self):
        """Tests a double spend caught when processing a transaction."""
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 15)
        card1.amount = 15

        # T1: Card1 SN=1 => Card2
        T1, sender_sig1 = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 14)
        T1, receiver_sig1 = card2.sign_receive(T1, sender_sig1)

        self.assertEqual(T1.evaluate(sender_sig1, receiver_sig1), self.MP)
        self.assertTrue(B.process_payment(T1, sender_sig1, receiver_sig1))

        # Card1 owner manually resets sn and amount values on the card and finds victim card3
        card1.sn = 0
        card1.amount = 15

        timestamp = 1700009007
        # card1 finds another victim that wins the lottery with payment
        card3 = Wallet(
            "a6474c40a58c6ef0ca4c0f79bfcf0d69fe8a0a23cc0fcb3b5c77a32eb2f7c6d3",
            0,
        )

        # T2: Card1 SN=1 => Card3 (double-spend)
        T2, sender_sig2 = card1.pay(card3.pubkey, 3, timestamp)
        self.assertEqual(card1.amount, 12)
        T2, receiver_sig2 = card3.sign_receive(T2, sender_sig2)

        # Test positive report case
        with self.assertRaises(ErrDoubleSpend):
            self.assertEqual(T2.evaluate(sender_sig2, receiver_sig2), self.MP)
            B.process_payment(T2, sender_sig2, receiver_sig2)

    def test_invalid_coin_interval(self):
        """Tests a case when the sender tries to send a coin that above the total number of received coins."""
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 9)
        card1.amount = 10

        T1, sender_sig1 = card1.pay(card2.pubkey, 10, timestamp)
        self.assertEqual(card1.amount, 0)
        T1, receiver_sig1 = card2.sign_receive(T1, sender_sig1)

        # Transaction is correctly signed but the user doesn't have enough funds
        self.assertEqual(T1.evaluate(sender_sig1, receiver_sig1), self.MP)

        with self.assertRaises(ErrInvalidCoinInterval):
            B.process_payment(T1, sender_sig1, receiver_sig1)

        # Deposit 1 coin and put it on the card. Now the bank can process it because it has the exact amount needed.
        B.deposit(card1.pubkey, 1)
        card1.amount = 10
        self.assertEqual(B.user_balance(card1.pubkey), 10)
        self.assertEqual(B.user_balance(card2.pubkey), 0)
        self.assertTrue(B.process_payment(T1, sender_sig1, receiver_sig1))
        self.assertEqual(B.user_balance(card1.pubkey), 0)
        self.assertEqual(B.user_balance(card2.pubkey), 10)

    def test_not_enough_funds(self):
        """Tests a case when the sender doesn't have enough funds to cover the transaction cost."""
        B = Bank()
        (card1, card2, timestamp) = self.cases["hit"]["1"]
        B.deposit(card1.pubkey, 9)
        card1.amount = 9

        T1, sender_sig1 = card1.pay(card2.pubkey, 1, timestamp)
        self.assertEqual(card1.amount, 8)
        T1, receiver_sig1 = card2.sign_receive(T1, sender_sig1)

        # Transaction is correctly signed but the user doesn't have enough funds
        self.assertEqual(T1.evaluate(sender_sig1, receiver_sig1), self.MP)

        with self.assertRaises(ErrNotEnoughFunds):
            B.process_payment(T1, sender_sig1, receiver_sig1)

        # Deposit 1 coin and put it on the card. Now the bank can process it because it has the exact amount needed.
        B.deposit(card1.pubkey, 1)
        card1.amount = 10
        self.assertEqual(B.user_balance(card1.pubkey), 10)
        self.assertEqual(B.user_balance(card2.pubkey), 0)
        self.assertTrue(B.process_payment(T1, sender_sig1, receiver_sig1))
        self.assertEqual(B.user_balance(card1.pubkey), 0)
        self.assertEqual(B.user_balance(card2.pubkey), 10)


if __name__ == "__main__":
    unittest.main()
