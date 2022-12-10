json = dofile('lua/rxi-json.lua')

local function url_encode (str)
    str = string.gsub(str, "([^0-9a-zA-Z !'()*._~-])", -- locale independent
            function(c)
                return string.format("%%%02X", string.byte(c))
            end)
    str = string.gsub(str, " ", "+")
    return str
end

local function url_decode (str)
    str = string.gsub(str, "+", " ")
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end

local function parse_query_params(query_string)
    local t = {}
    -- ?output_fields=title%2C+description&where=status+IN+('closed'%2C'new')+AND+caller_id+%3D+1
    for k, v in string.gmatch(query_string, "([%a_-]+)=([^&]+)") do
        t[k] = v
    end
    return t
end

local function decode_json_or_ret_error(data)
    local status, result = pcall(json.decode, data)
    if not status then
        -- Remove filename and string number from "lua/rxi-json.lua:185: control character in string at line 4 col 20",
        -- because the colon character breaks up the json log output and the gateway returns 500 code instead of 400.
        local msg = result:gsub('^.*:%d+:', '')
        custom_error("Failed to decode JSON - " .. msg, 400)
    end
    return result
end
-- uppercase params from endpoint urls: "/v1/{objectClass}/{objectId}"
local objectClassParam = 'ObjectClass'
local objectIdParam = 'ObjectId'
local stimulusParam = 'Stimulus'
local caseLogParam = 'CaseLog'

local function get_object_id_param(req)
    local objectId = req:params(objectIdParam)
    return string.match(objectId, "^[^0]%d*$")
end

-- defaults
local defaultOutputFields = 'id,friendlyname'
local defaultObjectsPerPageLimit = 100
local apiCommentEnv = "ITOP_API_COMMENT"
local defaultApiComment = os.getenv("KRAKEND_NAME") or 'Krakend API Gateway'

-- requests

local function modify_request(req, jsonData)
    --print(json.encode(jsonData));
    req:body('json_data=' .. url_encode(json.encode(jsonData)))
    req:headers('Content-Length', tostring(string.len(req:body())))
    req:headers('Content-Type', 'application/x-www-form-urlencoded')
    req:query('') -- do not send query params to backend
end

function create_object(req)
    local query = parse_query_params(req:query())
    local jsonData = {
        ['operation'] = 'core/create',
        ['class'] = req:params(objectClassParam),
        ['comment'] = query['api_comment'] and url_decode(query['api_comment']) or os.getenv(apiCommentEnv) or defaultApiComment,
        ['output_fields'] = query['output_fields'] and url_decode(query['output_fields']) or defaultOutputFields,
        ['fields'] = decode_json_or_ret_error(req:body())
    }
    modify_request(req, jsonData)
end

function get_object_by_id(req)
    local query = parse_query_params(req:query())
    local jsonData = {
        ['operation'] = 'core/get',
        ['class'] = req:params(objectClassParam),
        ['key'] = get_object_id_param(req),
        ['output_fields'] = query['output_fields'] and url_decode(query['output_fields']) or defaultOutputFields
    }
    modify_request(req, jsonData)
end

function get_object_list(req)
    local objClass = req:params(objectClassParam)
    local query = parse_query_params(req:query())
    local oqlFilter
    if query['filter'] then
        oqlFilter = url_decode(query['filter'])
    elseif query['where'] then
        oqlFilter = 'SELECT ' .. objClass .. " WHERE " .. url_decode(query['where'])
    else
        oqlFilter = 'SELECT ' .. objClass
    end
    local limit = tonumber(query['limit']) or defaultObjectsPerPageLimit;
    local page = tonumber(query['page']) or 1;
    -- store limit and page to make pagination in handle_list_response()
    req:params('Limit', tostring(limit))
    req:params('Page', tostring(page))

    local jsonData = {
        ['operation'] = 'core/get',
        ['class'] = objClass,
        ['key'] = oqlFilter,
        ['output_fields'] = query['output_fields'] and url_decode(query['output_fields']) or defaultOutputFields,
        ['limit'] = limit,
        ['page'] = page
    }
    modify_request(req, jsonData)
end

function update_object_by_id(req, withStimulus)
    local query = parse_query_params(req:query())
    local jsonData = {
        ['operation'] = 'core/update',
        ['class'] = req:params(objectClassParam),
        ['key'] = get_object_id_param(req),
        ['comment'] = query['api_comment'] and url_decode(query['api_comment']) or os.getenv(apiCommentEnv) or defaultApiComment,
        ['output_fields'] = query['output_fields'] and url_decode(query['output_fields']) or defaultOutputFields,
        ['fields'] = decode_json_or_ret_error(req:body())
    }
    if withStimulus then
        jsonData['operation'] = 'core/apply_stimulus'
        jsonData['stimulus'] = req:params(stimulusParam)
    end
    modify_request(req, jsonData)
end

function delete_object_by_id(req)
    local query = parse_query_params(req:query())
    local jsonData = {
        ['operation'] = 'core/delete',
        ['class'] = req:params(objectClassParam),
        ['key'] = get_object_id_param(req),
        ['comment'] = query['api_comment'] and url_decode(query['api_comment']) or os.getenv(apiCommentEnv) or defaultApiComment,
        ['simulate'] = query['simulate'] == 'true'
    }
    modify_request(req, jsonData)
end

function add_case_log_entry(req)
    local query = parse_query_params(req:query())
    local caseLogData = { [req:params(caseLogParam)] = { ['add_item'] = decode_json_or_ret_error(req:body()) } }
    local jsonData = {
        ['operation'] = 'core/update',
        ['class'] = req:params(objectClassParam),
        ['key'] = get_object_id_param(req),
        ['comment'] = query['api_comment'] and url_decode(query['api_comment']) or os.getenv(apiCommentEnv) or defaultApiComment,
        ['output_fields'] = req:params(caseLogParam),
        ['fields'] = caseLogData
    }
    modify_request(req, jsonData)
end

function get_case_log_entries(req)
    local jsonData = {
        ['operation'] = 'core/get',
        ['class'] = req:params(objectClassParam),
        ['key'] = get_object_id_param(req),
        ['output_fields'] = req:params(caseLogParam),
    }
    modify_request(req, jsonData)
end

-- responses

local function modify_response(res, statusCode, jsonData)
    res:statusCode(statusCode)
    local bodyString = json.encode(jsonData);
    res:body(bodyString)
    res:headers('Content-Length', tostring(string.len(bodyString)))
end

local function map_code_to_status(code, message)
    if code == 0 then
        return 200
    elseif code == 1 then
        -- 1 UNAUTHORIZED Missing/wrong credentials or the user does not have enough rights to perform the requested operation
        -- NOTE: actually iTop itself returns 401 with text/html for invalid credentials
        return 403
    elseif (code >= 2 and code <= 6) or code == 10 or code == 11 then
        -- Codes in the gateway's area of responsibility:
        -- 2 MISSING_VERSION The parameter 'version' is missing
        -- 3 MISSING_JSON The parameter 'json_data' is missing
        -- 4 INVALID_JSON The input structure is not a valid JSON string
        -- 5 MISSING_AUTH_USER The parameter 'auth_user' is missing
        -- 6 MISSING_AUTH_PWD The parameter 'auth_pwd' is missing or you are using url login type and it's not allowed on the Configuration file of your iTop
        -- 10 UNSUPPORTED_VERSION No operation is available for the specified version
        -- 11 UNKNOWN_OPERATION The requested operation is not valid for the specified version
        return 500
    elseif code == 12 then
        -- When deletion plan required manual operations:
        -- 12 UNSAFE The requested operation cannot be performed because it can cause data (integrity) loss
        return 422
    elseif code == 13 then
        -- 13 INVALID_PAGE The request page number is not valid. It must be an integer greater than 0
        return 400
    elseif code == 100 then
        -- 100 INTERNAL_ERROR The operation could not be performed, see the message for troubleshooting
        if string.find(message, '^Error: Unknown filter code')
                or string.find(message, '^Error: Unexpected input')
                or string.find(message, '^Error: Unexpected token')
                or string.find(message, '^Error: .+: Unknown attribute')
                or string.find(message, '^Error: Unexpected value for attribute')
                or string.find(message, '^Error: .+: invalid attribute code') then
            -- Error: Unknown filter code
            -- Error: Unexpected input
            -- Error: Unexpected token
            -- Error: {att_code}: Unknown attribute
            -- Error: Unexpected value for attribute
            -- Error: {param_name}: invalid attribute code
            return 400
        elseif string.find(message, '^Error: .+: No item found with criteria')
                or string.find(message, '^Error: .+: Invalid object')
                or string.find(message, '^Missing mandatory attribute%(s%) for applying the stimulus')
                or string.find(message, '^Invalid stimulus: \'.+\' on the object')
                or string.find(message, '^Error: Found issue%(s%): target_class =') then
            -- Error: {att_code}: No item found with criteria – When trying to set a non-existent object as a property value using JSON
            -- Error: {att_code}: Invalid object – When trying to set a non-existent object as a property value using Id
            -- Missing mandatory attribute(s) for applying the stimulus
            -- Invalid stimulus: '{stimulus}' on the object
            -- Error: Found issue(s): target_class = {class}, target_id = {id} – When deletion plan required manual operations
            return 422
        elseif string.find(message, '^Error: Invalid object %w+::%d+') then
            -- Error: Invalid object UserRequest::33432 – When trying to update a non-existent object
            return 404
        else
            return 500
        end
    else
        return 500
    end
end

local function handle_unexpected_content(res)
    if not string.match(res:headers('Content-Type'), 'application/json') then
        local bodyString
        if res:statusCode() == 200 then
            res:statusCode(502)
        end
        local message = 'Unexpected response content: ' .. string.sub(res:body(), 0, 1000) .. '... (cropped)';
        bodyString = json.encode({ ['message'] = message })
        res:body(bodyString)
        res:headers('Content-Length', tostring(string.len(bodyString)))
        res:headers('Content-Type', 'application/json')
        return true
    end
end

function handle_object_response(res)
    if handle_unexpected_content(res) then
        return
    end

    local resData = json.decode(res:body())
    local resStatus = map_code_to_status(resData.code, resData.message)

    if resData.objects then
        for key, object in pairs(resData.objects) do
            resData = object
        end
    else
        if resStatus == 200 then
            resStatus = 404
        end
        resData.objects = nil
    end

    modify_response(res, resStatus, resData)
end

function handle_create_response(res)
    handle_object_response(res)
    if res:statusCode() == 200 then
        res:statusCode(201)
    end
end

function handle_list_response(res, page, limit)
    if handle_unexpected_content(res) then
        return
    end

    local resData = json.decode(res:body())
    local resStatus = map_code_to_status(resData.code, resData.message)

    if resStatus == 200 then
        local objects = {}
        local count = 0
        if resData.objects then
            for key, object in pairs(resData.objects) do
                count = count + 1
                objects[count] = object
            end
        end
        resData.objects = objects
        resData.pagination = {
            ['count'] = count,
            ['page'] = tonumber(page),
            ['limit'] = tonumber(limit),
            ['total'] = tonumber(string.match(resData.message, "Found: (%d+)"))
        }
    end

    modify_response(res, resStatus, resData)
end

function handle_delete_response(res)
    if handle_unexpected_content(res) then
        return
    end

    local resData = json.decode(res:body())
    local resStatus = map_code_to_status(resData.code, resData.message)

    if resStatus == 200 then
        local objects = {}
        local count = 0
        if resData.objects then
            for key, object in pairs(resData.objects) do
                count = count + 1
                objects[count] = object
            end
        else
            resStatus = 404
        end
        resData.objects = objects
    end

    modify_response(res, resStatus, resData)
end

function handle_case_log_response(res, caseLog)
    if handle_unexpected_content(res) then
        return
    end

    local resData = json.decode(res:body())
    local resStatus = map_code_to_status(resData.code, resData.message)

    if resData.objects then
        for key, object in pairs(resData.objects) do
            resData = object
            resData[caseLog] = object['fields'][caseLog]['entries']
            resData['fields'] = nil
        end
    else
        if resStatus == 200 then
            resStatus = 404
        end
        resData.objects = nil
    end
    resData['objects'] = nil
    modify_response(res, resStatus, resData)
end