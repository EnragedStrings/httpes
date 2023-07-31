local component = require("component")
local computer = require("computer")
local serial = require("serialization")
local term = require("term")
local process = require("process")
local event = require("event")
local fs = require("filesystem")
local thread = require("thread")
local m = require("component").modem
local data = require("component").data
local uuid = require("uuid")

local debug = false

local function debugprint(...)
    if debug then
        print(...)
    end
end

--Required Base Functions

---Ensures flags are formatted correctly, additionally, returns a bool for each flag
---Example: flagChecker(
---{enable = true, disable = true, string = false},
---{enable = false, disable = true, string = "Default"})
---
---Returns: 
---flags = {enable = true, disable = true, string = "Default"}, 
---flagBool = {enable = true, disable = false, string = false}
---@param flags 'table' Input flags to check
---@param check 'table' Input what type/default values for the flags
---@return flags The inputted flags checked/fixed
---@return flagBool true/false for each flag if its been changed
local function flagChecker(flags, check)
    local flagBool = {}
    if flags == nil then
        flags = {}
    end
    for flag, data in pairs(flags) do
        if (data == nil) or (type(data) ~= type(check[flag])) then
            data = check[flag]
            if type(check[flag]) == "bool" then
                flagBool[flag] = check[flag]
            else
                flagBool[flag] = false
            end
        else
            if type(data) == "bool" then
                flagBool[flag] = data
            elseif data ~= check[flag] then
                flagBool[flag] = true
            else
                flagBool[flag] = false
            end
        end
    end
    return flags, flagBool
end
---Encrypts data with the public key.
---@param data 'string' Input data for encryption
---@param publicKey 'string' Input the public key to encrypt the data
---@return data The encrypted data
local function encrypt(messagedata, publicKey)
    return data.encrypt(messagedata, publicKey)
end
---Decrypts data with the private key.
---@param data 'string' Input encrypted data for decryption
---@param privateKey 'string' Input the private key to decrypt the data
---@return data The decrypted data
local function decrypt(messagedata, privateKey)
    debugprint("DECRYPTING", privateKey, messagedata)
    return data.decrypt(messagedata, privateKey)
end
---Sends the data to the UUID and port specified, with provided flags.
---@param UUID 'UUID | string' the UUID of the recieving modem
---@param port 'integer' The port for the recipient to recieve on
---@param data 'table | string' The data to send. Serializes before sending
---@param flags 'table' Flags include {publicKey = [STRING]}
---@return bool if sucessfully sent or not
local function sendData(UUID, port, data, flags)
    local flags, flagBool = flagChecker(flags, {publicKey = ""})
    debugprint("UNSERIALIZED: ", data.HEADER, data.TYPE, data.METHOD)
    debugprint("UNSERIALIZED: ", data.TO_SOCKET, data.FROM_SOCKET)
    local serialData = serial.serialize(data)
    if flagBool.publicKey then
        serialData = encrypt(serialData, flags.publicKey)
    end
    debugprint("SERIAL DATA: ", serialData)
    return m.send(UUID, port, serialData)
end
---Creates a public and private key.
---@return 'key' Public
---@return 'key' Private
local function createKeys()
    local pubKey, privKey = data.generateKeyPair()
    pubKey = pubKey.serialize()
    privKey = privKey.serialize()
    return pubKey, privKey
end
---unserializes and decrypts (If need be) the data Input
---@param data 'string' the data that needs to be unserialized/decrypted
---@param key 'string' The private key to decrypt the data
---@param decrypt 'bool' 
---@return output The unserialized/decrypted table
function unserialize(data, key, decryptBool)
    local newData = data
    if key ~= nil and key ~= "" and decryptBool == true then
        newData = decrypt(newData, key)
    end
    newData = serial.unserialize(data)
    return newData
end

local defaultData = {
    HEADER = "",
    BODY = "",
    TYPE = "",
    METHOD = "",
    TO_SOCKET = "",
    FROM_SOCKET = "",
}
---Generates a new table filled with default data for sending messages
---@return newData 'table'
function newData()
    local newData = setmetatable({}, { __index = defaultData })
    return newData
end

local defaultMethod = {TYPE = "", callback = nil}

local defaultSocket = {
    UUID = "",
    address = "",
    port = 0,
    status = "DISCONNECTED",
    encrypted = false,
    selfKeys = {public = "", private = ""},
    otherKeys = {public = "", private = ""},
    methods = {},
    -- Other basic information about the socket can be added here.

    -- Functions

    ---Checks if the provided method is included in the sockets method
    ---@param method 'string' the method the function is checking for
    ---@return found 'bool' true/false if method was found
    ---@return callback 'function' Only returned if method was found
    checkMethods = function(self, method)
        debugprint("Checking For Callback Methodds")
        if self.methods[method] ~= nil then
            debugprint("Callback Found")
            return true, self.methods[method].callback
        else
            return false
        end
    end,
    ---Sends the given data to the sockets address
    ---@param data 'table' The data to send
    ---@return bool if sucessfully sent or not
    send = function(self, data)
      return sendData(self.address, self.port, data, {publicKey = self.otherKeys.public})
    end,
    ---Checks if the recieved message is for this socket, if so, unserializes, checks against methods, and calls applicable method
    ---@return data sent after callback
    ---@return bool if the message was for the socket
    checkEvent = function(self, localAddr, remoteAddr, from, port, distance, message, callbackBool)
        debugprint("Checking For Correct Socket")
        debugprint(from, self.address, port, self.port)
        if from == self.address and port == self.port then
            debugprint("Socket Found")
            local decrypt = function() if self.status == "CONNECTED" then return true else return false end end
            local data = unserialize(message, self.selfKeys.private, decrypt())
            local bool, callback = self:checkMethods(data.METHOD)
            if bool and (callbackBool == nil or callbackBool == true) then
                debugprint("Executing Callback")
                callback(data, self)
            end
            return data, true, callback
        else
            debugprint("Wrong Socket")
            return nil, false, nil
        end
    end,
    ---Listens for incomming messages for the socket
    listen = function(self)
        event.listen("modem_message", self.checkEvent)
    end,
    ---Pulls incoming messages for the socket
    ---@param callback 'bool' if the function should execute the callback function
    ---@return data the incoming data
    ---@return callback if one was found, else 'nil'
    pull = function(self, callback)
        debugprint("Pulling Data...")
        local localAddr, remoteAddr, from, port, distance, message = event.pull("modem_message")
        local data, bool, callbackFunction = self:checkEvent(localAddr, remoteAddr, from, port, distance, message, callback)
        while bool == false do
            localAddr, remoteAddr, from, port, distance, message = event.pull("modem_message")
            data, bool, callbackFunction = self:checkEvent(localAddr, remoteAddr, from, port, distance, message, callback)
        end
        debugprint("Got Data")
        return data, callbackFunction
    end,
    handshake = function(self)
        self.status = "DISCONNECTED"
        local data = newData()
        data.METHOD = "HANDSHAKE"
        data.BODY = self.selfKeys.public
        data.TYPE = "CONNECT"
        data.HEADER = "SEND"
        data.FROM_SOCKET = self.UUID
        debugprint("Sending Handshake...")
        debugprint(data.FROM_SOCKET)
        if sendData(self.address, self.port, data) then
            self.status = "CONNECTING"
            return true
        else
            return false
        end
    end,
    ping = function(self)
      -- Implementation for ping functionality.
    end,
    ---Opens the socket's port
    ---@return bool if opened or not
    open = function(self)
        debugprint("Opening Socket")
        return m.open(self.port)
    end,
    ---Closes the socket's port
    ---@return bool if closed or not
    close = function(self)
        return m.close(self.port)
    end,
    ---Sets the sockets self public and private keys
    ---@param self 'self'
    ---@param public 'string' Public Key
    ---@param private 'string' Private Key
    setOwnKeys = function(self, public, private)
        self.selfKeys.public = public
        self.selfKeys.private = private
    end,
    ---Sets the sockets other public and private keys
    ---@param self 'self'
    ---@param public 'string' Public Key
    ---@param private 'string' Private Key
    setOtherKeys = function(self, public, private)
        self.otherKeys.public = public
        self.otherKeys.private = private
    end,
    ---Creates a new method for the socket. Triggers when socket & method gets called from incoming data.
    ---@param self 'self'
    ---@param TYPE 'string'
    ---@param callback 'function'
    ---@return method the created method
    newMethod = function(self, TYPE, callback)
        local method = setmetatable({}, { __index = defaultMethod })
        method.TYPE = TYPE
        method.callback = callback
        self.methods[TYPE] = method
        return self.methods[TYPE]
    end,

    ---Returns a bool if the socket is connected or not
    ---@param self 'self'
    ---@return bool connected
    connected = function(self)
        if socket.status == "CONNECTED" then
            return true
        else
            return false
        end
    end,
    -- Other functions can be added as needed.
}

---Creates a new socket for sending/recieving messages
---You can use functions with this socket
---@param address 'UUID | string' the modem address to send to
---@param port 'integer' the port to send on
---@param encrypted 'bool' whether to encrypt data or not
---@return socket
function createSocket(address, port, encrypted)
    debugprint("Creating Socket")
    local socket = setmetatable({}, { __index = defaultSocket })
    socket.UUID = uuid.next()
    socket.address = address
    socket.port = port
    socket.encrypted = encrypted
    debugprint("Creating Keys")
    socket:setOwnKeys(createKeys())
    debugprint("Creating Handshake Method")
    socket:newMethod("HANDSHAKE", function(data, self)
        debugprint("HANDSHAKE CALLBACK")
        if data.HEADER == "SEND" and self.status == "DISCONNECTED" then
            debugprint("SENDING RETURN HANDSHAKE")
            self.otherKeys.public = data.BODY
            local response = newData()
            response.METHOD = "HANDSHAKE"
            response.BODY = self.selfKeys.public
            response.TYPE = "CONNECT"
            response.HEADER = "RECIEVE"
            response.FROM_SOCKET = self.UUID
            response.TO_SOCKET = data.FROM_SOCKET
            if sendData(self.address, self.port, response) then
                self.status = "CONNECTED"
                return true
            else
                return false
            end
        elseif data.HEADER == "RECIEVE" and self.status == "CONNECTING" and data.TO_SOCKET == self.UUID then
            debugprint("GOT RETURN HANDSHAKE")
            self.status = "CONNECTED"
        else
            debugprint("UNEXPECTED ERROR")
            debugprint(data.HEADER, self.status, data.TO_SOCKET, self.UUID)
        end
    end)
    debugprint("Creating Ping Method")
    socket:newMethod("PING", function()
        --PUT PING CODE HERE
    end)
    -- Other socket-specific initializations can be done here.
    debugprint("Socket Created")
    return socket
end
