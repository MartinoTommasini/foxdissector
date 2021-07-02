-- Fox Niagara protocol dissector

-- Declare our protocol
fox = Proto("fox", "Niagara Fox")

-- Constants
--
-- Fox packets start with "fox "
local magic_sequence_len = 4

-- Lookup table for fox frame types
local frameTypes = {
	a = "Asynchronous",
	s = "Synchronous",
	k = "Keep-alive",
	r = "Reply",
	e = "Error",
	n = "F_NULL",
	['?'] = "Unknown"
}

function parse_blob(offset, buffer, tree, key, value_rel_offset)
	-- get size of blob
	local _, _end, size = buffer(offset + value_rel_offset):string():find("([%d]+)%[")
	
	if not size then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couln't find number of bytes in blob data")
		return 
	end

	-- + 1 for the ]
	local key_tree = tree:add_le(fox, buffer(offset, value_rel_offset + _end + size + 1), key..": ")

	if size == "3" then
		key_tree:append_text("empty")
	else
	 	local value = buffer(offset + value_rel_offset + _end, size):string()
		key_tree:append_text("[Content-Length] "..size.." bytes")
		key_tree:add_le(fox, buffer(offset, value_rel_offset + _end + size + 1), value)
	end
	-- +1 for ']'
	return _end + size + 1
end

function parse_float(offset, buffer, tree, key, value_rel_offset)
	local _, _end, value = buffer(offset + value_rel_offset):string():find("([%d%.]+)") -- TODO: test this regex
	
	if not value then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couldn't find float value")
		return 
	end

	tree:add_le(fox, buffer(offset, value_rel_offset + _end), key .. ":", value)

	return #value
end


function parse_int(offset, buffer, tree, key, value_rel_offset)
	local _, _end, value = buffer(offset + value_rel_offset):string():find("([%d]+)")

	if not value then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couldn't find int value")
		return 
	end

	tree:add_le(fox, buffer(offset, value_rel_offset + _end), key .. ":", value)

	return #value
end

function parse_message(offset, buffer, tree, key, value_rel_offset)
	-- get all message data (take everything between curly brackets)
	local relOffset = offset + value_rel_offset
	local start_index, end_index, message = buffer(relOffset):string():find("{\n(.-)}\n")
	local value

	-- eat { and \n 
	relOffset =  relOffset + 2 -- offset is passed by value to this function
	
	-- message format not correct
	if not message then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couldn't find the message data")
		return 
	end

	local message_tree = tree:add_le(fox, buffer(offset), key..":", " [Fox message]")
	
	if message:len() < 1 then
		-- message empty
		message_tree:append_text(" empty")
	else
		-- same logic of fox_parse_payload(). We don't reuse it to have more flexibility and readability.
		while true do	
			local str_buf = buffer(relOffset):string()
	
			-- exit if buffer starts with terminator sequence
			if str_buf:sub(0,2) == "}\n" then
				break
			end
			
			-- parse tuple key and data type 
			local _, _end, key, t = str_buf:find("([%S][%S]-)=([%l][%l]-):") 
			if not key or not t then
				message_tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": tuple not correct")
				return 
			end
	
			-- get appropriate parser
			local do_parse = get_parser[t]
			if not do_parse then
				message_tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Unknown data type encountered ("..t.."). Parser not available for this data type")
				return
			end
			-- parse tuple value
			local bytes_parsed = do_parse(relOffset, buffer, message_tree, key, _end)
	
			if not bytes_parsed then
				message_tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": A problem occurred when parsing the Fox payload")
				return
			end
	
			-- +1 for newline
			relOffset = relOffset + _end + bytes_parsed + 1
	
			-- Offset is expected to include the newline after each tuple
		end

	end

	-- -1 to excude newline
	message_tree:set_len(value_rel_offset + end_index - 1)

	-- -1 to exlude newline
	return end_index - 1

end

function parse_object(offset, buffer, tree, key, value_rel_offset)
	-- get type and size of object
	local _, _end, type, size = buffer(offset + value_rel_offset):string():find("([%S]+)%s([%d]+)%[")
	
	if not type then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couln't find type in object data")
		return 
	end

	if not size then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couln't find number of bytes in object data")
		return 
	end

	-- + 1 for the ]
	local key_tree = tree:add_le(fox, buffer(offset, value_rel_offset + _end + size + 1), key..": ")

	local value = buffer(offset + value_rel_offset + _end, size):string()  

	key_tree:append_text("[Object-Type] "..type..", ".."[Content-Length] "..size.." bytes")
	key_tree:add_le(fox, buffer(offset, value_rel_offset + _end + size + 1), value)

	-- +1 for ']'
	return _end + size + 1
end

function parse_string(offset, buffer, tree, key, value_rel_offset)
	local _, _end, value = buffer(offset + value_rel_offset):string():find("([%C%:]*)") 

	if not value then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couldn't find string value")
		return 
	end

	tree:add_le(fox, buffer(offset, value_rel_offset + _end), key .. ":", value)
	
	return #value
end

function parse_time(offset, buffer, tree, key, value_rel_offset)
	local _, _end, value = buffer(offset + value_rel_offset):string():find("([%x]+)")

	if not value then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Couldn't find time value")
		return 
	end

	local seconds = tonumber(value,16) / 1000

	local label
	if seconds < 31557600 then
		-- if year is 1970, value is likely a time duration (e.g. session stuff)
		label = "[HH:MM:SS] "..seconds_to_time(seconds)
	else
		-- year is not 1970, value is likely a timestamp
		label = "[Timestamp] "..seconds_to_timestamp(seconds).." UTC"		
	end

	tree:add_le(fox, buffer(offset, value_rel_offset + _end), key .. ": ", label)

	return #value
end

function parse_bool(offset, buffer, tree, key, value_rel_offset)
	local _, _end, value = buffer(offset + value_rel_offset):string():find("([tf])")

	if not value then
		tree:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Boolean value is neither t (true) or f (false)")
		return 
	end

	local label
	if value == "t" then
		label="true"
	else
		label="false"
	end

	tree:add_le(fox, buffer(offset, value_rel_offset + _end), key .. ":", label)

	return 1
end


--
-- Returns the suitable parser
-- depending on the data type 
-- 
-- Parameters of the parsers: (offset in buffer, buffer, parent tree, tuple key, offset of tuple value with respect to the beginning of tuple)
-- Return value of the parsers: (number of bytes parsed) 
--
get_parser =
{
  ["b"] = parse_blob,
  ["f"] = parse_float,
  ["i"] = parse_int,
  ["m"] = parse_message,
  ["o"] = parse_object,
  ["s"] = parse_string,
  ["t"] = parse_time,
  ["z"] = parse_bool,
}


function seconds_to_timestamp(epoch)
	return os.date("!%Y-%m-%d %X", epoch)
end

function seconds_to_time(epoch)
	return os.date("!%X", epoch)
end

-- Heuristic function
local function heur_dissect_fox(buffer, pinfo, tree)
	if buffer:len() < magic_sequence_len then
		print("Header to short to be fox")
		return false
	end
	
	-- Check if the command starts with "fox "
	if buffer(0, magic_sequence_len):string() ~= "fox " then
		print("Header Doesn't start w/ fox")
		return false
	end
	print("All good, moving to dissector")
	
	-- Looks like it's ours, so go dissect it
	fox.dissector(buffer, pinfo, tree)
	
	-- Since this is over a transport protocol, such as TCP, we can set the
	-- conversation to make it sticky for our dissector, so that all future
	-- packets to/from the same address:port pair will just call our dissector
	-- function directly instead of this heuristic function.
	pinfo.conversation = fox
	
	return true
end

-- Dissection functions
function fox.dissector(buffer, pinfo, tree)
	local offset = 0
	local buff_len = buffer:len()

    
    -- Handle multiple PDUs in one TCP segment
    while offset < buff_len do 

		-- Handle TCP defragmentation here
        -- 
		-- If we don't find the terminator '\n};;\n' ('0A7D3B3B0A'), then we accumulate the next packet.
		local str_buf = buffer:bytes(offset):tohex()
		local len_exc, len_inc = str_buf:find("0A7D3B3B0A")
		if not len_inc then
			pinfo.desegment_offset =  offset
			pinfo.desegment_len =  DESEGMENT_ONE_MORE_SEGMENT
			return 
		end

		-- At this point we have a full PDU in buffer

		pinfo.cols.protocol = "Niagara Fox"
		local pdu = tree:add_le(fox, buffer(offset), "Niagara Fox")
		local len_pdu = dissect_pdu(buffer(offset), pinfo, pdu)

		pdu:set_len(len_pdu)

		offset = offset + len_pdu
	end
end

function dissect_pdu(buffer, pinfo, pdu)
	local offset = 0
	local str = buffer(offset):string()
	local _, _,first_line = str:find("([^\n]+)")

	-- parse header
	offset = offset + fox_parse_header(offset, buffer, first_line, pdu, pinfo)

	-- Add two bytes to the offset to eat "{\n"
	offset = offset + 2

	-- parse fox payload
	local len_payload = fox_parse_payload(offset, buffer, pdu)
	if not len_payload then
		return 
	end

	-- Add payload length
	offset = offset + len_payload

	-- Add terminator sequence
	offset = offset + 4

	return offset 
end


function fox_parse_header(offset, buffer, line, parent,pinfo)
	local header = parent:add_le(fox, buffer(offset, offset + #line), "Header")

	-- Skip "fox "
	local relOffset = offset + 4

	-- e.g. "fox a -1 1 crypto keystore.getCertificates"
	_, _, ft, seq, reply, channel, command = 
		line:find("^fox (%w) (-?%d+) (-?%d+) (%C+) (%C+)$")

	header:add_le(fox, buffer(relOffset, 1), "Frame type:", frameTypes[ft])
	relOffset = relOffset + 2
	header:add_le(fox, buffer(relOffset, #seq), "Sequence number:", seq)
	relOffset = relOffset + #seq + 1
	header:add_le(fox, buffer(relOffset, #reply), "Reply number:", reply)
	relOffset = relOffset + #reply + 1
	header:add_le(fox, buffer(relOffset, #channel), "Channel:", channel)
	relOffset = relOffset + #channel + 1
	header:add_le(fox, buffer(relOffset, #command), "Command:", command)

	-- Display channel and command in the packet information
	pinfo.cols.info = channel.." command: "..command

	-- + 1 to account for the line break
	return #line + 1
end



function fox_parse_payload(offset, buffer, parent)
	local start_offset = offset 
	local data = parent:add_le(fox, buffer(offset), "Data segment")


	while true do	
		local str_buf = buffer(offset):string()

		-- exit if we find the terminator
		if str_buf:sub(0,4) == "};;\n" then
			-- If data segment is empty
			if offset == start_offset then	data:append_text(": empty") end

			break
		end
		
		-- parse tuple key and data type 
		--
		-- ([%S][%S]-) because we want to match the shortest possible sequence.
		local _, _end, key, t = str_buf:find("([%S][%S]-)=([%l][%l]-):") 
		if not key or not t then
			data:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing the payload data: format of data not correct. It should be (key=datatype:value)")
			return 
		end

		-- get appropriate parser
		local do_parse = get_parser[t]
		if not do_parse then
			data:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Unknown data type encountered ("..t.."). Parser not available for this data type")
			return
		end
		-- parse tuple value
		local bytes_parsed = do_parse(offset, buffer, data, key, _end)

		if not bytes_parsed then
			data:add_expert_info(PI_MALFORMED,PI_ERROR, "Error while parsing "..key..": Problem occurred when parsing the Fox payload")
			return
		end

		-- +1 for newline
		offset = offset + _end + bytes_parsed + 1

		-- Offset is expected to include the newline after each tuple
	end

	data:set_len(offset-start_offset)

	return offset 
end


-- Register our protocol with no specific port for TCP and UDP so it appears on the "Decode As..." menu
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, fox)

-- Now register that heuristic dissector into the TCP heuristic list
fox:register_heuristic("tcp", heur_dissect_fox)

