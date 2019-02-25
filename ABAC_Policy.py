'''
' Kody Johnson (1209950115)
' ASU CSE 365 - Information Assurance
' Last date modified - 2/17/2019
' Description: Implement ABAC policy with command line interface.
'''
import sys, argparse
class CommandLine:

	# DONE - Help function for storing and retrieving data from the storage file.
	def policyFetch(self, myChoice):
		try:
			attrs = ""
			perms = ""
			pa = ""
			entities = ""
			aa = ""
			t = open('policy.txt', 'r')
			line = t.readline()
			while line:
				parts = line.split("=")
				line = t.readline()
				if parts[0].strip() == 'ATTRS':
					if myChoice == 'ATTRS':
						attrs = parts[1].strip()
						return attrs
				elif parts[0].strip() == 'PERMS':
					if myChoice == 'PERMS':
						perms = parts[1].strip()
						return perms
				elif parts[0].strip() == 'PA':
					if myChoice == 'PA':
						pa = parts[1].strip()
						return pa
				elif parts[0].strip() == 'ENTITIES':
					if myChoice == 'ENTITIES':
						entities = parts[1].strip()
						return entities
				elif parts[0].strip() == 'AA':
					if myChoice == 'AA':
						aa = parts[1].strip()
						return aa
			t.close()
		except FileNotFoundError:
			print("") # Dont return anything if file is not found

	# DONE - Helper function to parse the attributes and returns the assignment of attributes.
	def fetchRole(self, attributeMatch):
		compare = ("<" + attributeMatch + ">")
		aa = self.policyFetch("AA")
		# Split ':' for individual attributes.
		attributeList = aa.split(';')
		for attribute in attributeList:
			attributeSplit = attribute.split(':')
			if attributeSplit[0].strip() == compare.strip():
				attributeSplitMore = attributeSplit[1].split(',')
				return attributeSplitMore[1].strip('>')
		return ("error")

	# DONE - Parser for attributes and permissions. ONLY HERE FOR REFERENCE. not used anywhere in code.
	def textParser(self, read_data):
		file_to_parse = read_data.split("-")
		for string in file_to_parse:
			print("Assignemnt Entry: " + string)
			file_parts = string.split(":")
			attributesLine = file_parts[0].strip()
			permissionName = file_parts[1].strip()				
			print("Attributes: " + str(attributesLine))
			print("Permission: " + str(permissionName))			
			attributes = attributesLine.split(";")
			for attribute in attributes:
				attribute = attribute.strip()
				attribute = attribute[1:len(attribute)-1]
				attributeParts = attribute.split(",")		
				name = attributeParts[0].strip()
				value = attributeParts[1].strip()
				print("Attribute name: " + name)
				print("Attribute value: " + value)
			print("--------------------------------------------------")
	
	# DONE - Function to load the policy and create a storage file for it.
	def loadPolicy(self, x):
		try:
			f = open(x, 'r')
			t = open('policy.txt', 'w')
			line = f.readline()
			while line:
				t.write(line)# store our policy in policy.txt
				parts = line.split("=")
				line = f.readline()
			f.close()
			t.close()
		except FileNotFoundError:
			print("") # Dont return anything if file is not found
		
	# DONE - Function to print out the policy.
	def showPolicy(self):
		try:
			p = open('policy.txt', 'r')
			line_p = p.read()
			print(line_p)	
		except FileNotFoundError:
			print("") # Dont return anything if file has not been loaded
		
	# DONE - Function that checks the permission of a user. - COMPLEX BOOLEAN.
	def checkPermission(self, userName, objectName, enviromentName, permissionNamet):
		# Best solved with somewhat complex boolean
		userCheck = False
		objectCheck = False
		enviromentCheck = False
		permissionCheck = False
		nameFetch = self.fetchRole(userName)
		objectFetch = self.fetchRole(objectName)
		enviromentFetch = self.fetchRole(enviromentName)
		paEntries = self.policyFetch("PA")
		parsedPA = paEntries.split("-")
		for string in parsedPA:
			file_parts = string.split(":")
			attributesLine = file_parts[0].strip()
			permissionName = file_parts[1].strip()					
			# Check permission first
			if permissionName == permissionNamet:
				permissionCheck = True	
				attributes = attributesLine.split(";")
				for attribute in attributes:
					attribute = attribute.strip()
					attribute = attribute[1:len(attribute)-1]
					attributeParts = attribute.split(",")		
					name = attributeParts[0].strip()
					value = attributeParts[1].strip()
					# Some boolean to help identify what values and roles are matching.
					if nameFetch.strip() == value.strip():
						userCheck = True
					elif objectFetch.strip() ==  value.strip():
						objectCheck = True
					elif enviromentFetch.strip() == value.strip():
						enviromentCheck = True
		# Check that all Bool values are true in order to grant permission.
		if permissionCheck == True and userCheck == True and objectCheck == True and enviromentCheck == True:
			print("Permission GRANTED!")
			return
		else:
			print("Permission DENIED!")
			return
		
	# DONE - Function that adds an entity to ENTITIES.
	def addEntity(self, entity):
		check = True
		newEntries = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		entityList = str(myEntities).split(';')
		for entries in entityList:
			if entries == entity:
				check = False
			elif entries != '':
				newEntries += (entries + ";")
		if check == True:
			newEntries += ("<" + entity + ">;")
			r = open('policy.txt', 'w') # open for writing
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(perms) + "\nPA = " + str(pa) + "\nENTITIES = " + str(newEntries) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
	
	# DONE - Function that deletes an entity from ENTITIES.
	def removeEntity(self, entityR):
		check = False
		newEntries = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		entityList = str(myEntities).split(';')
		entityRemove = ("<" + entityR + ">")
		for entries in entityList:
			if entries == entityRemove:
				check = True
			elif entries != '':
				newEntries += (entries + ";")
		if check == True:
			r = open('policy.txt', 'w')
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(perms) + "\nPA = " + str(pa) + "\nENTITIES = " + str(newEntries) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
		
	# DONE - Function that adds an attributes to ATTRS. Also ensures that if it already in there it doesnt repeat.	
	def addAttribute(self, attName, attType):
		check = True
		newAttributes = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		attributeList = str(attrs).split(';')
		for attributes in attributeList:
			aSplit = str(attributes).split(',')
			aType = aSplit[0]
			aName = aSplit[1]
			namePrint = aName.strip()
			typePrint = aType.strip()
			namePrint = namePrint.strip('>')
			typePrint = typePrint.strip('<')
			if namePrint.strip() == attName.strip() and typePrint.strip() == attType.strip():
				check = False
		if check == True:
			attrs += (";<" + attType.strip() + ", " + attName.strip() + ">")
			r = open('policy.txt', 'w')
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(perms) + "\nPA = " + str(pa) + "\nENTITIES = " + str(myEntities) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
	
	# Done? - Function that removes attributes from ATTRS and removes all PAs related to te attribute. ERROR with last entries being deleted need to catch the '-' so parse doesnt mess up later.
	def removeAttribute(self, attR):
		print("Attribute to be removen: " + attR)
		print("TODO")
		check = False
		newAttributes = ""
		newPA = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		print("my attributes: " + str(attrs))
		attributeList = str(attrs).split(';')
		print(str(attributeList))
		for attributes in attributeList:
			aSplit = str(attributes).split(',')
			aType = aSplit[0]
			aName = aSplit[1]
			namePrint = aName.strip()
			typePrint = aType.strip()
			namePrint = namePrint.strip('>')
			typePrint = typePrint.strip('<')
			print("aName: " + namePrint + " aType: " + typePrint)
			print("aName: " + namePrint)
			if namePrint.strip() != attR.strip():
				if attributes == attributeList[-1]:
					newAttributes += ("<" + typePrint.strip() + ", " + namePrint.strip() + ">")
				#elif attributeList[-2] == attributes and 
				else:
					newAttributes += ("<" + typePrint.strip() + ", " + namePrint.strip() + ">; ")
			elif namePrint.strip() == attR.strip():
				check == True
				print(attR + namePrint)
				# pa holds all PA's rewrite afterwards.
				# code for removin att from PAs
				paList = pa.split('-')
				print("My paList: " + str(paList))
				for myPa in paList:
					splitPA = myPa.split(':')
					print("myPa: " + splitPA[0] + "splitPA PERM: " + splitPA[1])
					splitEntries = splitPA[0].split(';')
					print("splitENTRIES: " + str(splitEntries))
					for attributes in splitEntries:
						splitAttribute = attributes.split(',')
						print("Current Attribute: " + attributes + "Split Attribute: " + str(splitAttribute))
						print("attribute name: " + splitAttribute[0] + " attribute value: " + splitAttribute[1])
						# Checking for attribute name here if in do not add back.
						compareR = ("<" + attR)
						if splitAttribute[0].strip() == compareR.strip():
							print("Removing:" + splitAttribute[0] + "==" + compareR)
						else:
							if attributes == splitEntries[-1]:
								newPA += (splitAttribute[0].strip() + ", " + splitAttribute[1].strip())
							else:
								newPA += (splitAttribute[0].strip() + ", " + splitAttribute[1].strip() + "; ")
							print("NEWPA: " + newPA)
							# if last attribute for a perm we delete the entire PA. ERROR here need to catch '-' at end
					if len(splitEntries) > 1:
						if myPa == paList[-1]:
							newPA += (" : " + splitPA[1].strip())
						else:
							newPA += (" : " + splitPA[1].strip() + " - ")
					else:
						print("HI")
				print("newPA" + newPA)
		
		if check == False:
			r = open('policy.txt', 'w')
			newFile = ("ATTRS = " + str(newAttributes) + "\nPERMS = " + str(perms) + "\nPA = " + str(newPA) + "\nENTITIES = " + str(myEntities) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
		
	# DONE - Adds a permission to PERMS and checks if it already has been added.
	def addPermission(self, perm):
		check = True
		newPermissions = ""
		entities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		myPermissions= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		permissionList = str(myPermissions).split(';')
		permissionCompare = ("<" + perm + ">")
		for permissions in permissionList:
			if permissions.strip() == permissionCompare.strip():
				check = False
			elif permissions != '':
				newPermissions += (permissions + ";")
		if check == True:
			newPermissions += (" <" + perm + ">")
			r = open('policy.txt', 'w')
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(newPermissions) + "\nPA = " + str(pa) + "\nENTITIES = " + str(entities) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
		
	# DONE - Remove a permission from PERMS and delete all entries of the permission from PA.
	def removePermission(self, rperm):
		check = False
		newPermissions = ""
		newPA = ""
		entities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		myPermissions= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		permissionList = str(myPermissions).split(';')
		permissionCompare = ("<" + rperm + ">")
		for permissions in permissionList:
			if permissions.strip() == permissionCompare.strip():
				check = True
			elif permissions != '':
				# catch in betweeen
				if permissions == permissionList[-1]:
					newPermissions += (permissions)
				# catch 2nd to last
				elif permissionCompare.strip() == permissionList[-1].strip() and permissions.strip() == permissionList[-2].strip():
					newPermissions += (permissions)
				else:
					newPermissions += (permissions + ";")
		if check == True:
			r = open('policy.txt', 'w')
			paList = str(pa).split('-')
			for paNumber in paList:
				split = str(paNumber).split(':')
				if split[1].strip() != rperm.strip():
					if paNumber == paList[-1]:
						newPA += paNumber
					else:
						newPA += (paNumber + "-")
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(newPermissions) + "\nPA = " + str(newPA) + "\nENTITIES = " + str(entities) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
		
	def addAttributesToPermission(self, permN, attN, attV):
		print("Permission name: " + permN + " Attribute Name: " + attN + " Attribute Value: " + attV)
		print("TODO AATP")
		
	def removeAttributesFromPermission(self, permN, attN, attV):
		print("Permission name: " + permN + " Attribute Name: " + attN + " Attribute Value: " + attV)
		print("TODO RAFP")
		
	def addAttributeToEntity(self, entN, attN, attV):
		print("Entity Name:" + entN + " Attribute Name: " + attN + " Attribute Value: " + attV)
		print("TODO AATE")
		
	def removeAttributeFromEntity(self, entN, attN, attV):
		print("Entity Name:" + entN + " Attribute Name: " + attN + " Attribute Value: " + attV)
		print("TODO RAFE")
		
	# Creating argument parsers for the commandline interface
	# load-policy, show-policy, check-permission, add-entity, remove-entity,
	# add-attribute, remove-attribute, add-permission, remove-permission,
	# add-attributes-to-permission,
	# remove-attribute-from-permission, add-attribute-to-entity, and 
	# remove-attribute-from-entity.
	
if __name__ == '__main__':
	
	# Create a parser for the CommandLine interface and create a subparser
	# set to destination command for storing user input.
	parser = argparse.ArgumentParser(description='Command line Interface Parser')
	subparser = parser.add_subparsers(dest='command')
	# Subparsers for our main parser. Note that all all parser have a default
	# TYPE=STR EVERYTHING BELOW IS DONE.

	# load-policy - done
	parser_lp = subparser.add_parser('load-policy', help='Parses a text file')
	
	# show-policy - done
	parser_sp = subparser.add_parser('show-policy', help='Display the already loaded policy')
	
	# check-permission
	parser_cp = subparser.add_parser('check-permission', help='Check permission')
		
	# add-entity - done
	parser_ae = subparser.add_parser('add-entity', help='Add entity to loaded policy')
	
	# remove-entity - done
	parser_re = subparser.add_parser('remove-entity', help='Remove entity to loaded policy')
	
	# add-attribute - done
	parser_aa = subparser.add_parser('add-attribute', help='Add attribute to loaded policy')
	
	# remove-attribute - done
	parser_ra = subparser.add_parser('remove-attribute', help='Remove attribute from loaded policy')
	
	# add-permission - done
	parser_ap = subparser.add_parser('add-permission', help='Add permission to loaded policy')
	
	# remove-permission - done
	parser_rp = subparser.add_parser('remove-permission', help='Remove permission from loaded policy')
	
	# add-attributes-to-permission - done
	parser_aatp = subparser.add_parser('add-attributes-to-permission', help='Add attribute to permission')
	
	# remove-attribute-from-permission - done
	parser_rafp = subparser.add_parser('remove-attribute-from-permission', help='Removes attribute from permission')
	
	# add-attribute-to-entity - done
	parser_aate = subparser.add_parser('add-attribute-to-entity', help='Add attribute to entity ')
	
	# remove-attriute-from-entity - done
	parser_rafe = subparser.add_parser('remove-attribute-from-entity', help='Remove attribute from entity')
	
	# Subcommands for all subparsers - Arguments are handled here via subparsers.
	par_lp = parser_lp.add_argument_group('Required Arguments')
	parser_lp.add_argument('file', nargs=1, metavar='file')
	
	par_cp = parser_cp.add_argument_group('Reguired Arguments') # -> multiple input need fix.
	parser_cp.add_argument('username', nargs=1, metavar = 'username')
	parser_cp.add_argument('objectname', nargs=1, metavar = 'objectname')
	parser_cp.add_argument('enviromentname', nargs=1, metavar = 'enviromentname')
	parser_cp.add_argument('permissionname', nargs=1, metavar = 'permissionname')
			
	par_ae = parser_ae.add_argument_group('Required Arguemnts')
	parser_ae.add_argument('entity', nargs=1, metavar='entity')
	
	par_re = parser_re.add_argument_group('Required Arguemnts')
	parser_re.add_argument('entityR', nargs=1, metavar='entityR')
	
	par_aa = parser_aa.add_argument_group('Required Arguments')
	parser_aa.add_argument('attributeN', nargs=1, metavar='attributeN')
	parser_aa.add_argument('attributeT', nargs=1, metavar='attributeT')
	
	par_ra = parser_ra.add_argument_group('Required Arguments')
	parser_ra.add_argument('attributeR', nargs=1, metavar='attributeR')
	
	par_ap = parser_ap.add_argument_group('Required Arguments')
	parser_ap.add_argument('permission', nargs=1, metavar='permission')
	
	par_rp = parser_rp.add_argument_group('Required Arguments')
	parser_rp.add_argument('permissionR', nargs=1, metavar='permissionR')
	
	par_aatp = parser_aatp.add_argument_group('Required Arguments')
	parser_aatp.add_argument('permissionN', nargs=1, metavar='permissionN')
	parser_aatp.add_argument('attributeN', nargs=1, metavar='attributeN')
	parser_aatp.add_argument('attributeV', nargs=1, metavar='attributeV')
	
	par_rafp = parser_rafp.add_argument_group('Required Arguemnts')
	parser_rafp.add_argument('permissionN', nargs=1, metavar='permissionN')
	parser_rafp.add_argument('attributeN', nargs=1, metavar='attributeN')
	parser_rafp.add_argument('attributeV', nargs=1, metavar='attributeV')
	
	par_aate = parser_aate.add_argument_group('Required Arguemnts')
	parser_aate.add_argument('entityN', nargs=1, metavar='entityN')
	parser_aate.add_argument('attributeN', nargs=1, metavar='attributeN')
	parser_aate.add_argument('attributeV', nargs=1, metavar='attributeV')
	
	par_rafe = parser_rafe.add_argument_group('Required Arguments')
	parser_rafe.add_argument('entityN', nargs=1, metavar='entityN')
	parser_rafe.add_argument('attributeN', nargs=1, metavar='attributeN')
	parser_rafe.add_argument('attributeV', nargs=1, metavar='attributeV')
	
	# Create object from above class to make calls to its functions.
	commander = CommandLine()
	args = parser.parse_args()
		
	# Checking the command inputed by the user and calling the proper function command.
	if args.command == 'load-policy':
		data_show = commander.loadPolicy(args.file[0])
	elif args.command == 'show-policy':
		commander.showPolicy()
	elif args.command == 'check-permission':
		commander.checkPermission(args.username[0], args.objectname[0], args.enviromentname[0], args.permissionname[0])
	elif args.command == 'add-entity':
		commander.addEntity(args.entity[0])
	elif args.command == 'remove-entity':
		commander.removeEntity(args.entityR[0])
	elif args.command == 'add-attribute':
		commander.addAttribute(args.attributeN[0], args.attributeT[0])
	elif args.command == 'remove-attribute':
		commander.removeAttribute(args.attributeR[0])
	elif args.command == 'add-permission':
		commander.addPermission(args.permission[0])
	elif args.command == 'remove-permission':
		commander.removePermission(args.permissionR[0])
	elif args.command == 'add-attributes-to-permission':
		commander.addAttributesToPermission(args.permissionN[0], args.attributeN[0], args.attributeV[0])
	elif args.command == 'remove-attribute-from-permission':
		commander.removeAttributesFromPermission(args.permissionN[0], args.attributeN[0], args.attributeV[0])
	elif args.command == 'add-attribute-to-entity':
		commander.addAttributeToEntity(args.entityN[0], args.attributeN[0], args.attributeV[0])
	elif args.command == 'remove-attribute-from-entity':
		commander.removeAttributeFromEntity(args.entityN[0], args.attributeN[0], args.attributeV[0])
	else:
		sys.exit(0) # Any system error is defaulted to system exit. Otherwise the command entered was not properly labeled.
