import PySimpleGUI as Psg
import main as scapy_main

Psg.theme('TealMono')
Psg.set_options(font='Courier 11', button_element_size=(10, 2))
HEADING_LIST = ["Source", "Destination", "Source Port",
					"Destination Port", "Payload", "Actual Payload"]
DATA_LIST = []


def MainMenuWindow():
	layout = [[Psg.Button("Sniffer", key="sniffer"), Psg.Exit()]]
	
	return Psg.Window(title="Scapy",
					  layout=layout,
					  location=(800, 600),
					  finalize=True)


def PacketSniffer():
	right_click_menu = ['&Right', ['Packet Analysis', 'Packet Decoding', 'Packet Manipulation']]
	data = [scapy_main.packet_sniffer()]
	try:
		DATA_LIST.append([data[0].get('Source'), data[0].get("Destination"), str(data[0].get("SPort")),
						  str(data[0].get("DPort")), data[0].get("Payload"), data[0].get("ActualPayload")])
	except AttributeError:
		DATA_LIST.append(["None", "None", "None",
					  "None", "None", "None"])
	
	layout = [[Psg.Table(values=DATA_LIST,
						 headings=HEADING_LIST,
						 max_col_width=100,
						 auto_size_columns=True,
						 justification='left',
						 key='-TABLE-',
						 enable_events=True,
						 right_click_menu=right_click_menu)],
			  [Psg.Button('Packet Analysis', key='analysis', visible=False),
			   Psg.Button('Packet Decoding', key='decoding', visible=False),
			   Psg.Button('Packet Manipulation', key='manipulate', visible=False)],
			  [Psg.Button("Refresh", key="refresh"), Psg.Exit()]]
	
	return [Psg.Window(title="Packet Sniffer",
					  layout=layout,
					  finalize=True), DATA_LIST]


def PacketAnalysis(data_list):
	layout = [[Psg.Text(HEADING_LIST[0] + ":"), Psg.InputText(data_list[0], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[1] + ":"), Psg.InputText(data_list[1], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[2] + ":"), Psg.InputText(data_list[2], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[3] + ":"), Psg.InputText(data_list[3], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[4] + ":"), Psg.InputText(data_list[4], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[5] + ":"), Psg.InputText('None' if data_list[5] is None else data_list[5],
															  pad=(0, 0),
															  readonly=True)],
			  [Psg.Exit()]]
	
	return Psg.Window(title="Packet Analysis",
					  layout=layout,
					  finalize=True)


def PacketDecoding(hex_data):
	layout = [[Psg.Text(HEADING_LIST[5] + ":"), Psg.InputText("None" if hex_data is None else
															  scapy_main.packet_decoding(hex_data),
															  pad=(0, 0),
															  readonly=True)],
			  [Psg.Exit()]]

	return Psg.Window(title="Packet Decoding",
					  layout=layout,
					  finalize=True)


def PacketManipulation(data_list):
	layout = [[Psg.Text(HEADING_LIST[0] + ":"), Psg.InputText(data_list[0], pad=(0, 0), key="src")],
			  [Psg.Text(HEADING_LIST[1] + ":"), Psg.InputText(data_list[1], pad=(0, 0), key="dst")],
			  [Psg.Text(HEADING_LIST[2] + ":"), Psg.InputText(data_list[2], pad=(0, 0), key="sport")],
			  [Psg.Text(HEADING_LIST[3] + ":"), Psg.InputText(data_list[3], pad=(0, 0), key="dport")],
			  [Psg.Text(HEADING_LIST[4] + ":"), Psg.InputText(data_list[4], pad=(0, 0), readonly=True)],
			  [Psg.Text(HEADING_LIST[5] + ":"), Psg.InputText('None' if data_list[5] is None else data_list[5],
															  pad=(0, 0), key="Payload")],
			  [Psg.Button("Submit", key="submit"), Psg.Exit()]]
	
	return Psg.Window(title="Packet Manipulation",
					  layout=layout,
					  finalize=True)


def PacketSnifferFunc():
	retval = PacketSniffer()
	packet_sniffer_window, data_list = retval[0], retval[1]
	while True:
		event, values = packet_sniffer_window.read()
		
		if event in (Psg.WIN_CLOSED, "Exit"):
			break
			
		elif event == "-TABLE-":
			data_selected = [data_list[row] for row in values[event]]
			packet_sniffer_window['analysis'].update(visible=True)
			packet_sniffer_window['decoding'].update(visible=True)
			packet_sniffer_window['manipulate'].update(visible=True)
			
		elif event == "analysis":
			PacketAnalysisFunc(data_selected[0])
		
		elif event == 'decoding':
			PacketDecodingFunc(hex_data=None) if data_selected[0][5] is None else \
				PacketDecodingFunc(hex_data=data_selected[0][5])
		
		elif event == 'manipulate':
			PacketManipulationFunc(data_selected[0])
		
		elif event == "refresh":
			packet_sniffer_window.close()
			PacketSnifferFunc()
	
	packet_sniffer_window.close()


def PacketAnalysisFunc(data):
	packet_analysis_window = PacketAnalysis(data_list=data)
	while True:
		event, values = packet_analysis_window.read()
		
		if event in (Psg.WIN_CLOSED, "Exit"):
			break
		
	packet_analysis_window.close()


def PacketDecodingFunc(hex_data):
	packet_decoding_window = PacketDecoding(hex_data)
	while True:
		event, values = packet_decoding_window.read()
		
		if event in (Psg.WIN_CLOSED, "Exit"):
			break
	
	packet_decoding_window.close()


def PacketManipulationFunc(data):
	packet_manipulation_window = PacketManipulation(data)
	while True:
		event, values = packet_manipulation_window.read()
		
		if event in (Psg.WIN_CLOSED, "Exit"):
			break
		elif event == "submit":
			packet_data = [values.get('src'), values.get('dst'),
						   int(values.get('sport')), int(values.get('dport')),
						   values.get('Payload')]
			scapy_main.packet_manipulation(packet_data)
			
	packet_manipulation_window.close()


def main():
	main_menu_window = MainMenuWindow()
	while True:
		event, values = main_menu_window.read()
		
		if event in (Psg.WIN_CLOSED, "Exit"):
			break
		elif event == "sniffer":
			PacketSnifferFunc()

	main_menu_window.close()


if __name__ == "__main__":
	main()
	
