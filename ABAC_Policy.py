'''
' Kody Johnson (1209950115)
' ASU CSE 365 - Information Assurance
' Last date modified - 2/16/2019
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
				else:
					print("Unkown Entry: " + parts[1].strip())
			t.close()
			# returs list

		except FileNotFoundError:
			print("") # Dont return anything if file is not found

	# DONE - Parser for attributes and permissions.
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
				if parts[0].strip() == 'ATTRS':
					print("ATTRS: " + parts[1].strip())
					attrs = parts[1].strip()
				elif parts[0].strip() == 'PERMS':
					print("PERMS: " + parts[1].strip())
					perms = parts[1].strip()
				elif parts[0].strip() == 'PA':
					print("PA: " + parts[1].strip())
					self.textParser(parts[1])
				elif parts[0].strip() == 'ENTITIES':
					print("ENTITIES: " + parts[1].strip())
					entities = parts[1].strip()
				elif parts[0].strip() == 'AA':
					print("AA: " + parts[1].strip())
					aa = parts[1].strip()
				else:
					print("Unkown Entry: " + parts[1].strip())
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
		
	# WORK - Function that checks the permission of a user.
	def checkPermission(self, userName, objectName, enviromentName, permissionName):
		print("Username: " + userName + " Objectname: " + objectName + " Enviromentname: " + enviromentName + " PermissionName: " + permissionName)
		# Work HERE
		
	# DONE - Function that adds an entity to ENTITIES.
	def addEntity(self, entity):
		check = True
		newEntries = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		print("myEntities: " + str(myEntities))
		entityList = str(myEntities).split(';')
		print(str(entityList))
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
	
	# DONE - Function that deletes an entity from ENTITIES. Also deletes all appearances of that entity.
	def removeEntity(self, entityR):
		check = False
		newEntries = ""
		myEntities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		perms= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		print("myEntities: " + str(myEntities))
		entityList = str(myEntities).split(';')
		print(str(entityList))
		entityRemove = ("<" + entityR + ">")
		print("entityRemove: " + entityRemove)
		for entries in entityList:
			if entries == entityRemove:
				print("Compare" + entries + "to" + entityRemove)
				check = True
				print("CHECK: " + str(check))
			elif entries != '':
				print("New entry added: " + entries)
				newEntries += (entries + ";")
			print("NEWENTRIES: " + str(newEntries))
		print("entityList: " + str(entityList))
		if check == True:
			r = open('policy.txt', 'w') # open for writing
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(perms) + "\nPA = " + str(pa) + "\nENTITIES = " + str(newEntries) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
			
	def addAttribute(self, attName, attType):
		print("Attribute Name: " + attName + " Attribute Type: " + attType)
		print("TODO")
	
	def removeAttribute(self, attR):
		print("Attribute to be removen: " + attR)
		print("TODO")
		
	# DONE - Adds a permission to PERMS and checks if it already has been added.
	def addPermission(self, perm):
		print("Add permission: " + perm)
		check = True
		newPermissions = ""
		entities = self.policyFetch("ENTITIES")
		attrs = self.policyFetch("ATTRS")
		myPermissions= self.policyFetch("PERMS")
		pa = self.policyFetch("PA")
		aa = self.policyFetch("AA")
		print("myPermissions: " + str(myPermissions))
		permissionList = str(myPermissions).split(';')
		print(str(permissionList))
		permissionCompare = ("<" + perm + ">")
		print("perm comp: " + permissionCompare)
		for permissions in permissionList:
			if permissions.strip() == permissionCompare.strip():
				print("Compare" + permissions.strip() + "to" + permissionCompare)
				check = False
			elif permissions != '':
				newPermissions += (permissions + ";")
				print("new Permissions: " + newPermissions)
		if check == True:
			newPermissions += (" <" + perm + ">;")
			r = open('policy.txt', 'w') # open for writing
			newFile = ("ATTRS = " + str(attrs) + "\nPERMS = " + str(newPermissions) + "\nPA = " + str(pa) + "\nENTITIES = " + str(entities) + "\nAA = " + str(aa))
			r.write(newFile)
			r.close()
		
	def removePermission(self, rperm):
		print("Remove permission: " + rperm)
		try:
			o = open('policy.txt', 'r') # open for reading and writing.
			line = o.readline()
			check = False
			while line:
				parts = line.split("=")
				line = o.readline()
				if parts[0].strip() == 'ATTRS':
					attrs = parts[1].strip()
				elif parts[0].strip() == 'PERMS':
					perms = parts[1].strip()
					print("perms: " + perms)
					permCompare = ("<" + rperm + ">")
					permCompare = permCompare.upper()
					permList = parts[1].split(';')
					perms = ""
					print("permComp: " + permCompare)
					print("permList: " + str(permList))
					for numPerm in permList:
						print("numper: " + numPerm.strip())
						if numPerm.strip() == permCompare.strip(): # logic works need to locate work around for spaces in lists
							permRemove = str(permList)
							print("permremove: " + permRemove.strip())
							permList.remove(" " + permCompare)
							check = True
							print("Check: " + str(check))
						else:
							if permList[-1] == numPerm:
								perms += (numPerm)
								print("Perms after:" + perms)
							else:
								perms += (numPerm + ";")
								print("Perms after:" + perms)							
				elif parts[0].strip() == 'PA':
					pa = parts[1].strip()
				elif parts[0].strip() == 'ENTITIES':
					entities = parts[1].strip()
				elif parts[0].strip() == 'AA':
					aa = parts[1].strip()				
				else:
					print("")
			# Storage stuff
			o.close()
			if check == True:
				r = open('policy.txt', 'w') # open for writing
				newFile = ("ATTRS = " + attrs + "\nPERMS = " + perms + "\nPA = " + pa + "\nENTITIES = " + entities + "\nAA = " + aa)
				r.write(newFile)
				r.close()
		except FileNotFoundError:
			print("") # Dont return anything if policy has not been loaded.
		
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
	# TYPE=STR EVERYTHING BELOW IS DONE FOCUS ON FUNCTIONS

	# load-policy - done
	parser_lp = subparser.add_parser('load-policy', help='Parses a text file')
	
	# show-policy - done
	parser_sp = subparser.add_parser('show-policy', help='Display the already loaded policy')
	
	# check-permission
	parser_cp = subparser.add_parser('check-permission', help='Check permission')
		
	# add-entity - done
	parser_ae = subparser.add_parser('add-entity', help='Add entity to loaded policy')
	
	# remove-entity - somewhat done
	parser_re = subparser.add_parser('remove-entity', help='Remove entity to loaded policy')
	
	# add-attribute
	parser_aa = subparser.add_parser('add-attribute', help='Add attribute to loaded policy')
	
	# remove-attribute
	parser_ra = subparser.add_parser('remove-attribute', help='Remove attribute from loaded policy')
	
	# add-permission
	parser_ap = subparser.add_parser('add-permission', help='Add permission to loaded policy')
	
	# remove-permission
	parser_rp = subparser.add_parser('remove-permission', help='Remove permission from loaded policy')
	
	# add-attributes-to-permission
	parser_aatp = subparser.add_parser('add-attributes-to-permission', help='Add attribute to permission')
	
	# remove-attribute-from-permission
	parser_rafp = subparser.add_parser('remove-attribute-from-permission', help='Removes attribute from permission')
	
	# add-attribute-to-entity
	parser_aate = subparser.add_parser('add-attribute-to-entity', help='Add attribute to entity ')
	
	# remove-attriute-from-entity
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
		sys.exit(0)