#Code for Unit Testing

import unittest
import main as scapy_main

class TestScapyMain(unittest.TestCase):
	@classmethod
	def setUpClass(cls) -> None:
		cls.packet = scapy_main.packet_sniffer()
	
	def setUp(self) -> None:
		print("Starting Setup for {}.".format(self.id().split('.')[-1]))
		print("Setup Complete.")

	def tearDown(self) -> None:
			print("Starting Teardown.")
			print("Tearing complete for {}.".format(self.id().split('.')[-1]))
			print("-------------------------\n")

	def test_PacketSniffer(self):
			if self.packet  is None:
				self.assertTrue(isinstance(self.packet , type(None)))
			else:
				self.assertTrue(isinstance(self.packet , dict))

	def test_PacketDecoding(self):
		if self.packet  is None:
			self.assertTrue(isinstance(self.packet , type(None)))
		else:
			self.assertTrue(isinstance(scapy_main.packet_decoding(self.packet .get('ActualPayload')), str))

	def test_PacketManipulation(self):
		data = ['127.0.0.1', '127.0.0.1', 8080, 8081, 'hello']
		self.assertTrue(scapy_main.packet_manipulation(data))
		

if __name__ == "__main__":
	test_order = ["test_PacketSniffer", "test_PacketDecoding", "test_PacketManipulation"]
	test_loader = unittest.TestLoader()
	test_loader.sortTestMethodsUsing = lambda x, y: test_order.index(x) - test_order.index(y)
	unittest.main(testLoader=test_loader)
