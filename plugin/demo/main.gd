extends Node2D

var _plugin_name = "AndroidKeystorePlugin"
var _android_plugin

func _ready():
	if Engine.has_singleton(_plugin_name):
		_android_plugin = Engine.get_singleton(_plugin_name)
	else:
		printerr("Couldn't find plugin " + _plugin_name)

func _on_Button_pressed():
	if _android_plugin:

		print(_android_plugin.containsAlias("dropbox"))
		print("Generating key")
		_android_plugin.generateKey("dropbox")
		print(_android_plugin.containsAlias("dropbox"))
		print(_android_plugin.getCreationDate("dropbox"))
		var datetime = Time.get_datetime_dict_from_unix_time(_android_plugin.getCreationDate("dropbox"))
		print("Creation time: %04d-%02d-%02d %02d:%02d:%02d" % [
			datetime.year, datetime.month, datetime.day,
			datetime.hour, datetime.minute, datetime.second
		])
		print(_android_plugin.encryptString("my first test", "dropbox"))
		print(_android_plugin.decryptString(_android_plugin.encryptString("my first test", "dropbox"), "dropbox"))
		print("Deleting key")
		_android_plugin.deleteEntry("dropbox")
		print("Key deleted")
		print(_android_plugin.containsAlias("dropbox"))
		
		