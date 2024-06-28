
import json
import uuid
import asyncio
import websockets

class NetlinkClient:

	"""
	Client for the Netlink protocol, only on the websocket transport
	"""

	def __init__(self, uri, verbose=False):
		self.uri = uri
		self.receivedPacketsCounter = 0
		self.id = ''
		self.verbose = verbose
		self.websocket = None

	def isConnected(self) : return self.websocket != None

	# Override this with your own handler
	async def handleCommand(self, command = '', headers = {}, data = ''): 
		pass # default implementation does nothing

	# Override this with your own handler
	async def handleQuery(self, query = '', headers = {}, data = ''): 
		pass # default implementation does nothing

	async def sendCommand(self, command = '', headers = {}, data = ''):
		if self.websocket != None :
			commandHeaders = dict(headers)
			commandHeaders['command'] = command
			commandDict = { 'Headers' : commandHeaders, 'Data' : data }
			await self.websocket.send(json.dumps(commandDict))

	async def sendQuery(self, query = '', headers = {}, data = ''):
		if self.websocket != None :
			pass #TODO
			return None

	async def runAsync(self):
		# Continually connect
		async for websocket in websockets.connect(self.uri):
			try:
				print('connected')
				self.websocket = websocket
				async for message in websocket:
					await self.__process(message)
			except websockets.ConnectionClosed:
				print('disconnected')
				self.websocket = None
				continue

	def runSync(self):
		asyncio.run(self.runAsync())

	async def __process(self, message):
		if self.verbose : print(message)
		self.receivedPacketsCounter += 1
		if self.receivedPacketsCounter == 1 :
			self.id = message
		else :
			msgDict = json.loads(message)
			msgHeaders = json.loads(msgDict.get('Headers', '{}'))
			msgData = msgDict.get('Data','')
			if 'command' in msgHeaders :
				await self.handleCommand(msgHeaders['command'])
			elif 'query' in msgHeaders :
				response = await self.handleQuery(msgHeaders['query'])
				responseDict = { 'Headers' : { 'response': response }, 'QueryId' : msgDict['QueryId'], 'IsQueryResponse': True }
				await self.websocket.send(json.dumps(responseDict))


"""
Example usage
"""

if __name__ == '__main__' :

	async def myCommandHandler(command = '', headers = {}, data = ''):
		print('Custom Handling of command recveived from server:', command)

	async def myQueryHandler(query = '', headers = {}, data = ''):
		print('Custom Handling of query requested from server:', query)
		return 'Ok boss!'

	client = NetlinkClient('ws://localhost:5555', verbose = False)
	client.handleCommand = myCommandHandler
	client.handleQuery = myQueryHandler

	# only client <- server
	#client.runSync()

	# client <-> server
	async def listen_task() : await client.runAsync() # client <- server
	async def send_task(): # clirnt -> server
		while True:
			if client.isConnected() :
				await asyncio.sleep(4)
				await client.sendCommand('myCommand')
				await asyncio.sleep(1)
				response = await client.sendQuery('myQuery')
				print('Response from server', response)
			else :
				print('waiting for connection')
				await asyncio.sleep(1)


	async def tasks() : await asyncio.gather(listen_task(), send_task())
	asyncio.run(tasks())