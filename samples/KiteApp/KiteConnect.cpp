#include <string>
#include <cpprest/http_client.h> 
#include <cpprest/filestream.h> 
//----- Some standard C++ headers emitted for brevity
#include "cpprest/json.h" 
#include "cpprest/http_listener.h" 
#include "cpprest/uri.h" 
#include "cpprest/asyncrt_utils.h"
#include <boost/algorithm/string.hpp>

#include <iomanip>
#include <sstream>
#include <string>
#include <iostream>
#include <openssl/sha.h>
#include <memory>
//////////////////////////////////////////////// 
// A Simple HTTP Client to Demonstrate  
// REST SDK Client programming model 
// The Toy sample shows how one can read  
// contents of a web page 
// 
using namespace utility;  // Common utilities like string conversions 
using namespace web;      // Common features like URIs. 
using namespace web::http;// Common HTTP functionality 
using namespace web::http::client;// HTTP client features 
using namespace concurrency::streams;// Asynchronous streams
using namespace boost::algorithm;
using namespace std;      // Use std c++ features

/**
 * Offers all the functionality like placing order, fetch margins, orderbook, positions, fetch market snap quote.
 */
class KiteConnect {

    public:
         SessionExpiryHook sessionExpiryHook = null;
         boolean ENABLE_LOGGING = false;

    private:
        Proxy proxy = null;
        string apiKey;
        string accessToken;
        string publicToken;
        Routes routes = new Routes();
        string userId;
        Gson gson;
        shared_ptr<web::http::client::http_client> httpClient;

    private:

// START OF HTTP Functions

        /// <summary>
        /// Alias for sending a GET request.
        /// </summary>
        /// <param name="Route">URL route of API</param>
        /// <param name="Params">Additional paramerters</param>
        /// <returns>Varies according to API endpoint</returns>
        dynamic Get(string Route, map<string, string> Params = std::nullptr)
        {
            return Request(Route, methods::GET, Params);
        }

        /// <summary>
        /// Alias for sending a POST request.
        /// </summary>
        /// <param name="Route">URL route of API</param>
        /// <param name="Params">Additional paramerters</param>
        /// <returns>Varies according to API endpoint</returns>
        private dynamic Post(string Route, Dictionary<string, dynamic> Params = null)
        {
            return Request(Route, "POST", Params);
        }

        /// <summary>
        /// Alias for sending a PUT request.
        /// </summary>
        /// <param name="Route">URL route of API</param>
        /// <param name="Params">Additional paramerters</param>
        /// <returns>Varies according to API endpoint</returns>
        private dynamic Put(string Route, Dictionary<string, dynamic> Params = null)
        {
            return Request(Route, "PUT", Params);
        }

        /// <summary>
        /// Alias for sending a DELETE request.
        /// </summary>
        /// <param name="Route">URL route of API</param>
        /// <param name="Params">Additional paramerters</param>
        /// <returns>Varies according to API endpoint</returns>
        private dynamic Delete(string Route, Dictionary<string, dynamic> Params = null)
        {
            return Request(Route, "DELETE", Params);
        }

        /// <summary>
        /// Adds extra headers to request
        /// </summary>
        /// <param name="Req">Request object to add headers</param>
        private void AddExtraHeaders(ref HttpWebRequest Req)
        {
            var KiteAssembly = System.Reflection.Assembly.GetAssembly(typeof(Kite));
            if (KiteAssembly != null)
                Req.UserAgent = "KiteConnect.Net/" + KiteAssembly.GetName().Version;

            Req.Headers.Add("X-Kite-Version", "3");
            Req.Headers.Add("Authorization", "token " + _apiKey + ":" + _accessToken);

            //if(Req.Method == "GET" && cache.IsCached(Req.RequestUri.AbsoluteUri))
            //{
            //    Req.Headers.Add("If-None-Match: " + cache.GetETag(Req.RequestUri.AbsoluteUri));
            //}

            Req.Timeout = _timeout;
            if (_proxy != null) Req.Proxy = _proxy;

            if (_enableLogging)
            {
                foreach (string header in Req.Headers.Keys)
                {
                    Console.WriteLine("DEBUG: " + header + ": " + Req.Headers.GetValues(header)[0]);
                }
            }
        }

        /// <summary>
        /// Make an HTTP request.
        /// </summary>
        /// <param name="Route">URL route of API</param>
        /// <param name="Method">Method of HTTP request</param>
        /// <param name="Params">Additional paramerters</param>
        /// <returns>Varies according to API endpoint</returns>
        private dynamic Request(string Route, string Method, Dictionary<string, dynamic> Params = null)
        {
            string url = _root + _routes[Route];

            if (Params is null)
                Params = new Dictionary<string, dynamic>();

            if (url.Contains("{"))
            {
                var urlparams = Params.ToDictionary(entry => entry.Key, entry => entry.Value);

                foreach (KeyValuePair<string, dynamic> item in urlparams)
                    if (url.Contains("{" + item.Key + "}"))
                    {
                        url = url.Replace("{" + item.Key + "}", (string)item.Value);
                        Params.Remove(item.Key);
                    }
            }

            //if (!Params.ContainsKey("api_key"))
            //    Params.Add("api_key", _apiKey);

            //if (!Params.ContainsKey("access_token") && !String.IsNullOrEmpty(_accessToken))
            //    Params.Add("access_token", _accessToken);

            HttpWebRequest request;
            string paramString = String.Join("&", Params.Select(x => Utils.BuildParam(x.Key, x.Value)));

            if (Method == methods::POST || Method == methods::PUT)
            {
                request = (HttpWebRequest)WebRequest.Create(url);
                request.AllowAutoRedirect = true;
                request.Method = Method;
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = paramString.Length;
                if (_enableLogging) Console.WriteLine("DEBUG: " + Method + " " + url + "\n" + paramString);
                AddExtraHeaders(ref request);

                using (Stream webStream = request.GetRequestStream())
                using (StreamWriter requestWriter = new StreamWriter(webStream))
                    requestWriter.Write(paramString);
            }
            else
            {
                request = (HttpWebRequest)WebRequest.Create(url + "?" + paramString);
                request.AllowAutoRedirect = true;
                request.Method = Method;
                if (_enableLogging) Console.WriteLine("DEBUG: " + Method + " " + url + "?" + paramString);
                AddExtraHeaders(ref request);
            }

            WebResponse webResponse;
            try
            {
                webResponse = request.GetResponse();
            }
            catch (WebException e)
            {
                if (e.Response is null)
                    throw e;

                webResponse = e.Response;
            }

            using (Stream webStream = webResponse.GetResponseStream())
            {
                using (StreamReader responseReader = new StreamReader(webStream))
                {
                    string response = responseReader.ReadToEnd();
                    if (_enableLogging) Console.WriteLine("DEBUG: " + (int)((HttpWebResponse)webResponse).StatusCode + " " + response + "\n");

                    HttpStatusCode status = ((HttpWebResponse)webResponse).StatusCode;

                    if (webResponse.ContentType == "application/json")
                    {
                        Dictionary<string, dynamic> responseDictionary = Utils.JsonDeserialize(response);

                        if (status != HttpStatusCode.OK)
                        {
                            string errorType = "GeneralException";
                            string message = "";

                            if (responseDictionary.ContainsKey("error_type"))
                                errorType = responseDictionary["error_type"];

                            if (responseDictionary.ContainsKey("message"))
                                message = responseDictionary["message"];

                            switch (errorType)
                            {
                                case "GeneralException": throw new GeneralException(message, status);
                                case "TokenException":
                                    {
                                        _sessionHook?.Invoke();
                                        throw new TokenException(message, status);
                                    }
                                case "PermissionException": throw new PermissionException(message, status);
                                case "OrderException": throw new OrderException(message, status);
                                case "InputException": throw new InputException(message, status);
                                case "DataException": throw new DataException(message, status);
                                case "NetworkException": throw new NetworkException(message, status);
                                default: throw new GeneralException(message, status);
                            }
                        }

                        return responseDictionary;
                    }
                    else if (webResponse.ContentType == "text/csv")
                        return Utils.ParseCSV(response);
                    else
                        throw new DataException("Unexpected content type " + webResponse.ContentType + " " + response);
                }
            }
        }

// END OF HTTP REGION
    public:


    /** Initializes KiteSDK with the api key provided for your app.
     * @param apiKey is the api key provided after creating new Kite Connect app on developers console.
     */
    KiteConnect(string apiKey){
        this(apiKey, null, false);
    }

    /** Initializes KiteSDK with the api key provided for your app.
     * @param apiKey is the api key provided after creating new Kite Connect app on developers console.
     * @param enableDebugLog is a boolean to enable debug logs
     */
    KiteConnect(string apiKey, boolean enableDebugLog){
        this(apiKey, null, enableDebugLog);
    }

    /** Initializes KiteSDK with the api key provided for your app.
     * @param apiKey is the api key provided after creating new Kite Connect app on developers console.
     * @param userProxy is the user defined proxy. Can be used only if a user chose to use the proxy.
     */
    KiteConnect(string apiKey, Proxy userProxy, bool enableDebugLog, 
        std::chrono::seconds timeout = std::chrono::seconds(7)) {
        this.proxy = userProxy;
        this.apiKey = apiKey;
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Date.class, new JsonDeserializer<Date>() {
            @Override
            public Date deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
                try {
                    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    return format.parse(jsonElement.getAsstring());
                } catch (ParseException e) {
                    return null;
                }
            }
        });
        gson = gsonBuilder.setDateFormat("yyyy-MM-dd HH:mm:ss").create();
        ENABLE_LOGGING = enableDebugLog;

        // Http related initializations
        Routes route; // TODO: Define it
        http_client_config clientConfig;
        clientConfig.set_timeout(timeout);
        if(userProxy != nullptr) {
            clientConfig.set_proxy(userProxy);
        }
        httpClient = make_unique<http_client>(route.GetRoot(), clientConfig); //Fill in the root url
    }

    /** Registers callback for session error.
     * @param hook can be set to get callback when session is expired.
     * */
    void setSessionExpiryHook(SessionExpiryHook hook){
        sessionExpiryHook = hook;
    }

    /**
     *  Returns apiKey of the App.
     * @return  string apiKey is returned.
     * @throws NullPointerException if _apiKey is not found.
     */
    string getApiKey() throws NullPointerException{
        if (apiKey != null)
            return apiKey;
        else
            throw new NullPointerException();
    }

    /**
     * Returns accessToken.
     * @return string access_token is returned.
     * @throws NullPointerException if accessToken is null.
     */
    string getAccessToken() throws NullPointerException{
        if(accessToken != null)
            return accessToken;
        else
            throw new NullPointerException();
    }

    /** Returns userId.
     * @return string userId is returned.
     * @throws  NullPointerException if userId is null.*/
    string getUserId() throws NullPointerException{
        if(userId != null) {
            return userId;
        }else {
            throw new NullPointerException();
        }
    }

    /** Set userId.
     * @param id is user_id. */
    void setUserId(string id){
        userId = id;
    }

    /** Returns publicToken.
     * @throws NullPointerException if publicToken is null.
     * @return string public token is returned.
     * */
    string getPublicToken() throws NullPointerException{
        if(publicToken != null){
            return publicToken;
        }else {
            throw new NullPointerException();
        }
    }

    /**
     * Set the accessToken received after a successful authentication.
     * @param accessToken is the access token received after sending request token and api secret.
     */
    void setAccessToken(string accessToken){
        this.accessToken = accessToken;
    }

    /**
     * Set publicToken.
     * @param publicToken is the public token received after sending request token and api secret.
     * */
    void setPublicToken(string publicToken){
        this.publicToken = publicToken;
    }

    /** Retrieves login url
     * @return string loginUrl is returned. */
    string getLoginURL() throws NullPointerException{
        string baseUrl = routes.getLoginUrl();
        return baseUrl+"?api_key="+apiKey+"&v=3";
    }

    /**
     * Do the token exchange with the `request_token` obtained after the login flow,
     * and retrieve the `access_token` required for all subsequent requests.
     * @param requestToken received from login process.
     * @param apiSecret which is unique for each aap.
     * @return User is the user model which contains user and session details.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    User generateSession(string requestToken, string apiSecret) throws KiteException, JSONException, IOException {

        // Create the checksum needed for authentication.
        string hashableText = this.apiKey + requestToken + apiSecret;
        string sha256hex = sha256Hex(hashableText);

        // Create JSON params object needed to be sent to api.
        Map<string, Object> params = new HashMap<string, Object>();
        params.put("api_key", apiKey);
        params.put("request_token", requestToken);
        params.put("checksum", sha256hex);

        return  new User().parseResponse(kiteRequestHandler.postRequest(routes.get("api.validate"), params, apiKey, accessToken));
    }

    /** Get a new access token using refresh token.
     * @param refreshToken is the refresh token obtained after generateSession.
     * @param apiSecret is unique for each app.
     * @return TokenSet contains user id, refresh token, api secret.
     * @throws IOException is thrown when there is connection error.
     * @throws KiteException is thrown for all Kite trade related errors. */
    TokenSet renewAccessToken(string refreshToken, string apiSecret) throws IOException, KiteException, JSONException {
        string hashableText = this.apiKey + refreshToken + apiSecret;
        string sha256hex = sha256Hex(hashableText);

        Map<string, Object> params = new HashMap<>();
        params.put("api_key", apiKey);
        params.put("refresh_token", refreshToken);
        params.put("checksum", sha256hex);

        JSONObject response = kiteRequestHandler.postRequest(routes.get("api.refresh"), params, apiKey, accessToken);
        return gson.fromJson(string.valueOf(response.get("data")), TokenSet.class);
    }

    /** Hex encodes sha256 output for android support.
     * @return Hex encoded string.
     * @param str is the string that has to be encrypted.
     * */
    string sha256Hex(string str) {
        byte[] a = DigestUtils.sha256(str);
        stringBuilder sb = new stringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(string.format("%02x", b));
        return sb.tostring();
    }

    /** Get the profile details of the use.
     * @return Profile is a POJO which contains profile related data.
     * @throws IOException is thrown when there is connection error.
     * @throws KiteException is thrown for all Kite trade related errors.*/
    Profile getProfile() throws IOException, KiteException, JSONException {
        string url = routes.get("user.profile");
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return gson.fromJson(string.valueOf(response.get("data")), Profile.class);
    }

    /**
     * Gets account balance and cash margin details for a particular segment.
     * Example for segment can be equity or commodity.
     * @param segment can be equity or commodity.
     * @return Margins object.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Margin getMargins(string segment) throws KiteException, JSONException, IOException {
        string url = routes.get("user.margins.segment").replace(":segment", segment);
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return gson.fromJson(string.valueOf(response.get("data")), Margin.class);
    }

    /**
     * Gets account balance and cash margin details for a equity and commodity.
     * @return Map of string and Margin is a map of commodity or equity string and funds data.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Map<string, Margin> getMargins() throws KiteException, JSONException, IOException {
        string url = routes.get("user.margins");
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        Type type = new TypeToken<Map<string, Margin>>(){}.getType();
        return gson.fromJson(string.valueOf(response.get("data")), type);
    }

    /**
     * Places an order.
     * @param orderParams is Order params.
     * @param variety variety="regular". Order variety can be bo, co, amo, regular.
     * @return Order contains only orderId.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Order placeOrder(OrderParams orderParams, string variety) throws KiteException, JSONException, IOException {
        string url = routes.get("orders.place").replace(":variety", variety);

        Map<string, Object> params = new HashMap<>();

        if(orderParams.exchange != null) params.put("exchange", orderParams.exchange);
        if(orderParams.tradingsymbol != null) params.put("tradingsymbol", orderParams.tradingsymbol);
        if(orderParams.transactionType != null) params.put("transaction_type", orderParams.transactionType);
        if(orderParams.quantity != null) params.put("quantity", orderParams.quantity);
        if(orderParams.price != null) params.put("price", orderParams.price);
        if(orderParams.product != null) params.put("product", orderParams.product);
        if(orderParams.orderType != null) params.put("order_type", orderParams.orderType);
        if(orderParams.validity != null) params.put("validity", orderParams.validity);
        if(orderParams.disclosedQuantity != null) params.put("disclosed_quantity", orderParams.disclosedQuantity);
        if(orderParams.triggerPrice != null) params.put("trigger_price", orderParams.triggerPrice);
        if(orderParams.squareoff != null) params.put("squareoff", orderParams.squareoff);
        if(orderParams.stoploss != null) params.put("stoploss", orderParams.stoploss);
        if(orderParams.trailingStoploss != null) params.put("trailing_stoploss", orderParams.trailingStoploss);
        if(orderParams.tag != null) params.put("tag", orderParams.tag);

        JSONObject jsonObject = kiteRequestHandler.postRequest(url, params, apiKey, accessToken);
        Order order =  new Order();
        order.orderId = jsonObject.getJSONObject("data").getstring("order_id");
        return order;
    }

    /**
     * Modifies an open order.
     *
     * @param orderParams is Order params.
     * @param variety variety="regular". Order variety can be bo, co, amo, regular.
     * @param orderId order id of the order being modified.
     * @return Order object contains only orderId.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Order modifyOrder(string orderId, OrderParams orderParams, string variety) throws KiteException, JSONException, IOException {
        string url = routes.get("orders.modify").replace(":variety", variety).replace(":order_id", orderId);

        Map<string, Object> params = new HashMap<>();

        if(orderParams.exchange != null) params.put("exchange", orderParams.exchange);
        if(orderParams.tradingsymbol != null) params.put("tradingsymbol", orderParams.tradingsymbol);
        if(orderParams.transactionType != null) params.put("transaction_type", orderParams.transactionType);
        if(orderParams.quantity != null) params.put("quantity", orderParams.quantity);
        if(orderParams.price != null) params.put("price", orderParams.price);
        if(orderParams.product != null) params.put("product", orderParams.product);
        if(orderParams.orderType != null) params.put("order_type", orderParams.orderType);
        if(orderParams.validity != null) params.put("validity", orderParams.validity);
        if(orderParams.disclosedQuantity != null) params.put("disclosed_quantity", orderParams.disclosedQuantity);
        if(orderParams.triggerPrice != null) params.put("trigger_price", orderParams.triggerPrice);
        if(orderParams.squareoff != null) params.put("squareoff", orderParams.squareoff);
        if(orderParams.stoploss != null) params.put("stoploss", orderParams.stoploss);
        if(orderParams.trailingStoploss != null) params.put("trailing_stoploss", orderParams.trailingStoploss);
        if(orderParams.parentOrderId != null) params.put("parent_order_id", orderParams.parentOrderId);

        JSONObject jsonObject = kiteRequestHandler.putRequest(url, params, apiKey, accessToken);
        Order order =  new Order();
        order.orderId = jsonObject.getJSONObject("data").getstring("order_id");
        return order;
    }

    /**
     * Cancels an order.
     * @param orderId order id of the order to be cancelled.
     * @param variety [variety="regular"]. Order variety can be bo, co, amo, regular.
     * @return Order object contains only orderId.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Order cancelOrder(string orderId, string variety) throws KiteException, JSONException, IOException {
        string url = routes.get("orders.cancel").replace(":variety", variety).replace(":order_id", orderId);
        Map<string, Object> params = new HashMap<string, Object>();

        JSONObject jsonObject = kiteRequestHandler.deleteRequest(url, params, apiKey, accessToken);
        Order order =  new Order();
        order.orderId = jsonObject.getJSONObject("data").getstring("order_id");
        return order;
    }

    /**
     * Cancel/exit special orders like BO, CO
     * @param parentOrderId order id of first leg.
     * @param orderId order id of the order to be cancelled.
     * @param variety [variety="regular"]. Order variety can be bo, co, amo, regular.
     * @return Order object contains only orderId.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection error.
     * */
    Order cancelOrder(string orderId, string parentOrderId, string variety) throws KiteException, IOException, JSONException {
        string url = routes.get("orders.cancel").replace(":variety", variety).replace(":order_id", orderId);

        Map<string, Object> params = new HashMap<>();
        params.put("parent_order_id", parentOrderId);

        JSONObject jsonObject = kiteRequestHandler.deleteRequest(url, params, apiKey, accessToken);
        Order order =  new Order();
        order.orderId = jsonObject.getJSONObject("data").getstring("order_id");
        return order;
    }

    /** Fetches collection of orders from the orderbook.
     * @return List of orders.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     * */
    List<Order> getOrders() throws KiteException, JSONException, IOException {
        string url = routes.get("orders");
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), Order[].class));
    }

    /** Fetches list of gtt existing in an account.
    * @return List of GTTs.
    * @throws KiteException is thrown for all Kite trade related errors.
    * @throws IOException is thrown when there is connection error.
    * */
    List<GTT> getGTTs() throws KiteException, IOException, JSONException {
        string url = routes.get("gtt");
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), GTT[].class));
    }

    /** Fetch details of a GTT.
     * @param gttId is the id of the GTT that needs to be fetched.
     * @return GTT object which contains all the details.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection error.
     * @throws JSONException is thrown when there is exception while parsing response.
     * */
    GTT getGTT(int gttId) throws IOException, KiteException, JSONException {
        string url = routes.get("gtt.info").replace(":id", gttId+"");
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return gson.fromJson(string.valueOf(response.get("data")), GTT.class);
    }

    /** Place a GTT.
     * @param gttParams is GTT param which container condition, type, order details. It can contain one or two orders.
     * @throws IOException  is thrown when there is connection error.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @return GTT object contains only gttId.*/
    GTT placeGTT(GTTParams gttParams) throws IOException, KiteException, JSONException {
        string url = routes.get("gtt.place");
        Map<string, Object> params = new HashMap<>();
        Map<string, Object> conditionParam = new HashMap<>();
        JSONArray ordersParam = new JSONArray();

        conditionParam.put("exchange", gttParams.exchange);
        conditionParam.put("tradingsymbol", gttParams.tradingsymbol);
        conditionParam.put("trigger_values", gttParams.triggerPrices.toArray());
        conditionParam.put("last_price", gttParams.lastPrice);
        conditionParam.put("instrument_token", gttParams.instrumentToken);

        for(GTTParams.GTTOrderParams order : gttParams.orders) {
            JSONObject gttOrderItem = new JSONObject();
            gttOrderItem.put("exchange", gttParams.exchange);
            gttOrderItem.put("tradingsymbol", gttParams.tradingsymbol);
            gttOrderItem.put("transaction_type", order.transactionType);
            gttOrderItem.put("quantity", order.quantity);
            gttOrderItem.put("price", order.price);
            gttOrderItem.put("order_type", order.orderType);
            gttOrderItem.put("product", order.product);
            ordersParam.put(gttOrderItem);
        }

        params.put("condition", new JSONObject(conditionParam).tostring());
        params.put("orders", ordersParam.tostring());
        params.put("type", gttParams.triggerType);

        JSONObject response = kiteRequestHandler.postRequest(url, params, apiKey, accessToken);
        GTT gtt = new GTT();
        gtt.id = response.getJSONObject("data").getInt("trigger_id");
        return gtt;
    }

    /** Modify a GTT.
     * @param gttParams is GTT param which container condition, type, order details. It can contain one or two orders.
     * @param gttId is the id of the GTT to be modified.
     * @throws IOException  is thrown when there is connection error.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @return GTT object contains only gttId.*/
    GTT modifyGTT(int gttId, GTTParams gttParams) throws IOException, KiteException, JSONException {
        string url = routes.get("gtt.modify").replace(":id", gttId+"");
        Map<string, Object> params = new HashMap<>();
        Map<string, Object> conditionParam = new HashMap<>();
        JSONArray ordersParam = new JSONArray();

        conditionParam.put("exchange", gttParams.exchange);
        conditionParam.put("tradingsymbol", gttParams.tradingsymbol);
        conditionParam.put("trigger_values", gttParams.triggerPrices.toArray());
        conditionParam.put("last_price", gttParams.lastPrice);
        conditionParam.put("instrument_token", gttParams.instrumentToken);

        for(GTTParams.GTTOrderParams order : gttParams.orders) {
            JSONObject gttOrderItem = new JSONObject();
            gttOrderItem.put("exchange", gttParams.exchange);
            gttOrderItem.put("tradingsymbol", gttParams.tradingsymbol);
            gttOrderItem.put("transaction_type", order.transactionType);
            gttOrderItem.put("quantity", order.quantity);
            gttOrderItem.put("price", order.price);
            gttOrderItem.put("order_type", order.orderType);
            gttOrderItem.put("product", order.product);
            ordersParam.put(gttOrderItem);
        }

        params.put("condition", new JSONObject(conditionParam).tostring());
        params.put("orders", ordersParam.tostring());
        params.put("type", gttParams.triggerType);

        JSONObject response = kiteRequestHandler.putRequest(url, params, apiKey, accessToken);
        GTT gtt = new GTT();
        gtt.id = response.getJSONObject("data").getInt("trigger_id");
        return  gtt;
    }

    /**
     * Cancel GTT.
     * @param gttId order id of first leg.
     * @return GTT object contains only gttId.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection error.
     * @throws JSONException is thrown when there is exception while parsing response.
     * */
    GTT cancelGTT(int gttId) throws IOException, KiteException, JSONException {
        string url = routes.get("gtt.delete").replace(":id", gttId+"");
        JSONObject response  = kiteRequestHandler.deleteRequest(url, new HashMap<>(), apiKey, accessToken);
        GTT gtt = new GTT();
        gtt.id = response.getJSONObject("data").getInt("trigger_id");
        return gtt;
    }

    /** Returns list of different stages an order has gone through.
     * @return List of multiple stages an order has gone through in the system.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @param orderId is the order id which is obtained from orderbook.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection error.
     * */
    List<Order> getOrderHistory(string orderId) throws KiteException, IOException, JSONException {
        string url = routes.get("order").replace(":order_id", orderId);
        JSONObject response = kiteRequestHandler.getRequest(url, apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), Order[].class));
    }

    /**
     * Retrieves list of trades executed.
     * @return List of trades.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    List<Trade> getTrades() throws KiteException, JSONException, IOException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("trades"), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), Trade[].class));
    }

    /**
     * Retrieves list of trades executed of an order.
     * @param orderId order if of the order whose trades are fetched.
     * @return List of trades for the given order.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    List<Trade> getOrderTrades(string orderId) throws KiteException, JSONException, IOException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("orders.trades").replace(":order_id", orderId), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), Trade[].class));
    }

    /**
     * Retrieves the list of holdings.
     * @return List of holdings.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    List<Holding> getHoldings() throws KiteException, JSONException, IOException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("portfolio.holdings"), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), Holding[].class));
    }

    /**
     * Retrieves the list of positions.
     * @return List of positions.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    Map<string, List<Position>> getPositions() throws KiteException, JSONException, IOException {
        Map<string, List<Position>> positionsMap = new HashMap<>();
        JSONObject response = kiteRequestHandler.getRequest(routes.get("portfolio.positions"), apiKey, accessToken);
        JSONObject allPositions = response.getJSONObject("data");
        positionsMap.put("net", Arrays.asList(gson.fromJson(string.valueOf(allPositions.get("net")), Position[].class)));
        positionsMap.put("day", Arrays.asList(gson.fromJson(string.valueOf(allPositions.get("day")), Position[].class)));
        return positionsMap;
    }


    /**
     * Modifies an open position's product type. Only an MIS, CNC, and NRML positions can be converted.
     * @param tradingSymbol Tradingsymbol of the instrument  (ex. RELIANCE, INFY).
     * @param exchange Exchange in which instrument is listed (NSE, BSE, NFO, BFO, CDS, MCX).
     * @param transactionType Transaction type (BUY or SELL).
     * @param positionType day or overnight position
     * @param oldProduct Product code (NRML, MIS, CNC).
     * @param newProduct Product code (NRML, MIS, CNC).
     * @param quantity Order quantity
     * @return JSONObject  which will have status.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection error.
     */
    JSONObject convertPosition(string tradingSymbol, string exchange, string transactionType, string positionType, string oldProduct, string newProduct, int quantity) throws KiteException, JSONException, IOException {
        Map<string, Object> params = new HashMap<>();
        params.put("tradingsymbol", tradingSymbol);
        params.put("exchange", exchange);
        params.put("transaction_type", transactionType);
        params.put("position_type", positionType);
        params.put("old_product", oldProduct);
        params.put("new_product", newProduct);
        params.put("quantity", quantity);

        return kiteRequestHandler.putRequest(routes.get("portfolio.positions.modify"), params, apiKey, accessToken);
    }

    /**
     * Retrieves list of market instruments available to trade.
     *
     * 	 Response is array for objects. For example,
     * 	{
     * 		instrument_token: '131098372',
     *		exchange_token: '512103',
     *		tradingsymbol: 'NIDHGRN',
     *		name: 'NIDHI GRANITES',
     *		last_price: '0.0',
     *		expiry: '',
     *		strike: '0.0',
     *		tick_size: '0.05',
     *		lot_size: '1',
     *		instrument_type: 'EQ',
     *		segment: 'BSE',
     *		exchange: 'BSE' }, ...]
     * @return List of instruments which are available to trade.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related errors.
     */
    List<Instrument> getInstruments() throws KiteException, IOException, JSONException {
        return readCSV(kiteRequestHandler.getCSVRequest(routes.get("market.instruments.all"), apiKey, accessToken));
    }

    /**
     * Retrieves list of market instruments available to trade for an exchange
     *
     * 	 Response is array for objects. For example,
     * 	{
     * 		instrument_token: '131098372',
     *		exchange_token: '512103',
     *		tradingsymbol: 'NIDHGRN',
     *		name: 'NIDHI GRANITES',
     *		last_price: '0.0',
     *		expiry: '',
     *		strike: '0.0',
     *		tick_size: '0.05',
     *		lot_size: '1',
     *		instrument_type: 'EQ',
     *		segment: 'BSE',
     *		exchange: 'BSE' }, ...]
     * @param exchange  Filter instruments based on exchange. exchange can be NSE, BSE, NFO, BFO, CDS, MCX.
     * @return List of instruments which are available to trade for an exchange.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection related error.
     */
    List<Instrument> getInstruments(string exchange) throws KiteException, JSONException, IOException {
        return readCSV(kiteRequestHandler.getCSVRequest(routes.get("market.instruments").replace(":exchange", exchange), apiKey, accessToken));
    }

    /**
     * Retrieves quote and market depth for an instrument
     *
     * @param instruments is the array of tradingsymbol and exchange or instrument token. For example {NSE:NIFTY 50, BSE:SENSEX} or {256265, 265}
     *
     * @return Map of string and Quote.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection related error.
     */
    Map<string, Quote> getQuote(string [] instruments) throws KiteException, JSONException, IOException {
        JSONObject jsonObject = kiteRequestHandler.getRequest(routes.get("market.quote"), "i", instruments, apiKey, accessToken);
        Type type = new TypeToken<Map<string, Quote>>(){}.getType();
        return gson.fromJson(string.valueOf(jsonObject.get("data")), type);
    }

    /** Retrieves OHLC and last price.
     * User can either pass exchange with tradingsymbol or instrument token only. For example {NSE:NIFTY 50, BSE:SENSEX} or {256265, 265}
     * @return Map of string and OHLCQuote.
     * @param instruments is the array of tradingsymbol and exchange or instruments token.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    Map<string, OHLCQuote> getOHLC(string [] instruments) throws KiteException, IOException, JSONException {
        JSONObject resp = kiteRequestHandler.getRequest(routes.get("quote.ohlc"), "i", instruments, apiKey, accessToken);
        Type type = new TypeToken<Map<string, OHLCQuote>>(){}.getType();
        return gson.fromJson(string.valueOf(resp.get("data")), type);
    }

    /** Retrieves last price.
     * User can either pass exchange with tradingsymbol or instrument token only. For example {NSE:NIFTY 50, BSE:SENSEX} or {256265, 265}.
     * @return Map of string and LTPQuote.
     * @param instruments is the array of tradingsymbol and exchange or instruments token.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    Map<string, LTPQuote> getLTP(string[] instruments) throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("quote.ltp"), "i", instruments, apiKey, accessToken);
        Type type = new TypeToken<Map<string, LTPQuote>>(){}.getType();
        return gson.fromJson(string.valueOf(response.get("data")), type);
    }

    /**
     * Retrieves buy or sell trigger range for Cover Orders.
     * @return TriggerRange object is returned.
     * @param instruments is the array of tradingsymbol and exchange or instrument token.
     * @param transactionType "BUY or "SELL".
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws JSONException is thrown when there is exception while parsing response.
     * @throws IOException is thrown when there is connection related error.
     */
    Map<string, TriggerRange> getTriggerRange(string[] instruments, string transactionType) throws KiteException, JSONException, IOException {
        string url = routes.get("market.trigger_range").replace(":transaction_type", transactionType.toLowerCase());
        JSONObject response = kiteRequestHandler.getRequest(url, "i", instruments, apiKey, accessToken);
        Type type = new TypeToken<Map<string, TriggerRange>>(){}.getType();
        return gson.fromJson(string.valueOf(response.get("data")), type);
    }

    /** Retrieves historical data for an instrument.
     * @param from "yyyy-mm-dd" for fetching candles between days and "yyyy-mm-dd hh:mm:ss" for fetching candles between timestamps.
     * @param to "yyyy-mm-dd" for fetching candles between days and "yyyy-mm-dd hh:mm:ss" for fetching candles between timestamps.
     * @param continuous set to true for fetching continuous data of expired instruments.
     * @param interval can be minute, day, 3minute, 5minute, 10minute, 15minute, 30minute, 60minute.
     * @param token is instruments token.
     * @param oi set to true for fetching open interest data. The default value is 0.
     * @return HistoricalData object which contains list of historical data termed as dataArrayList.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    HistoricalData getHistoricalData(Date from, Date to, string token, string interval, boolean continuous, boolean oi) throws KiteException, IOException, JSONException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Map<string, Object> params = new HashMap<>();
        params.put("from", format.format(from));
        params.put("to", format.format(to));
        params.put("continuous", continuous ? 1 : 0);
        params.put("oi", oi ? 1 : 0);

        string url = routes.get("market.historical").replace(":instrument_token", token).replace(":interval", interval);
        HistoricalData historicalData = new HistoricalData();
        historicalData.parseResponse(kiteRequestHandler.getRequest(url, params, apiKey, accessToken));
        return historicalData;
    }

    /** Retrieves mutualfunds instruments.
     * @return returns list of mutual funds instruments.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related errors.
     * */
    List<MFInstrument> getMFInstruments() throws KiteException, IOException, JSONException {
        return readMfCSV(kiteRequestHandler.getCSVRequest(routes.get("mutualfunds.instruments"), apiKey, accessToken));
    }

    /** Place a mutualfunds order.
     * @return MFOrder object contains only orderId.
     * @param tradingsymbol Tradingsymbol (ISIN) of the fund.
     * @param transactionType BUY or SELL.
     * @param amount Amount worth of units to purchase. Not applicable on SELLs.
     * @param quantity Quantity to SELL. Not applicable on BUYs. If the holding is less than minimum_redemption_quantity, all the units have to be sold.
     * @param tag An optional tag to apply to an order to identify it (alphanumeric, max 8 chars).
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    MFOrder placeMFOrder(string tradingsymbol, string transactionType, double amount, double quantity, string tag) throws KiteException, IOException, JSONException {
        Map<string, Object> params = new HashMap<string, Object>();
        params.put("tradingsymbol", tradingsymbol);
        params.put("transaction_type", transactionType);
        params.put("amount", amount);
        if(transactionType.equals(Constants.TRANSACTION_TYPE_SELL)) params.put("quantity", quantity);
        params.put("tag", tag);

        JSONObject response = kiteRequestHandler.postRequest(routes.get("mutualfunds.orders.place"), params, apiKey, accessToken);
        MFOrder MFOrder = new MFOrder();
        MFOrder.orderId = response.getJSONObject("data").getstring("order_id");
        return MFOrder;
    }

    /** If cancel is successful then api will respond as 200 and send back true else it will be sent back to user as KiteException.
     * @return true if api call is successful.
     * @param orderId is the order id of the mutualfunds order.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there connection related error.
     * */
    boolean cancelMFOrder(string orderId) throws KiteException, IOException, JSONException {
        kiteRequestHandler.deleteRequest(routes.get("mutualfunds.cancel_order").replace(":order_id", orderId), new HashMap<string, Object>(), apiKey, accessToken);
        return true;
    }

    /** Retrieves all mutualfunds orders.
     * @return List of all the mutualfunds orders.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    List<MFOrder> getMFOrders() throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("mutualfunds.orders"), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), MFOrder[].class));
    }

    /** Retrieves individual mutualfunds order.
     * @param orderId is the order id of a mutualfunds scrip.
     * @return returns a single mutualfunds object with all the parameters.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    MFOrder getMFOrder(string orderId) throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("mutualfunds.order").replace(":order_id", orderId), apiKey, accessToken);
        return gson.fromJson(response.get("data").tostring(), MFOrder.class);
    }

    /** Place a mutualfunds sip.
     * @param tradingsymbol Tradingsymbol (ISIN) of the fund.
     * @param frequency weekly, monthly, or quarterly.
     * @param amount Amount worth of units to purchase. It should be equal to or greated than minimum_additional_purchase_amount and in multiple of purchase_amount_multiplier in the instrument master.
     * @param installmentDay If Frequency is monthly, the day of the month (1, 5, 10, 15, 20, 25) to trigger the order on.
     * @param instalments Number of instalments to trigger. If set to -1, instalments are triggered at fixed intervals until the SIP is cancelled.
     * @param initialAmount Amount worth of units to purchase before the SIP starts. Should be equal to or greater than minimum_purchase_amount and in multiple of purchase_amount_multiplier. This is only considered if there have been no prior investments in the target fund.
     * @return MFSIP object which contains sip id and order id.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    MFSIP placeMFSIP(string tradingsymbol, string frequency, int installmentDay, int instalments, int initialAmount, double amount) throws KiteException, IOException, JSONException {
        Map<string, Object> params = new HashMap<string, Object>();
        params.put("tradingsymbol", tradingsymbol);
        params.put("frequency", frequency);
        params.put("instalment_day", installmentDay);
        params.put("instalments", instalments);
        params.put("initial_amount", initialAmount);
        params.put("amount", amount);

        MFSIP MFSIP = new MFSIP();
        JSONObject response = kiteRequestHandler.postRequest(routes.get("mutualfunds.sips.place"),params, apiKey, accessToken);
        MFSIP.orderId = response.getJSONObject("data").getstring("order_id");
        MFSIP.sipId = response.getJSONObject("data").getstring("sip_id");
        return MFSIP;
    }

    /** Modify a mutualfunds sip.
     * @param frequency weekly, monthly, or quarterly.
     * @param status Pause or unpause an SIP (active or paused).
     * @param amount Amount worth of units to purchase. It should be equal to or greated than minimum_additional_purchase_amount and in multiple of purchase_amount_multiplier in the instrument master.
     * @param day If Frequency is monthly, the day of the month (1, 5, 10, 15, 20, 25) to trigger the order on.
     * @param instalments Number of instalments to trigger. If set to -1, instalments are triggered at fixed intervals until the SIP is cancelled.
     * @param sipId is the id of the sip.
     * @return returns true, if modify sip is successful else exception is thrown.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    boolean modifyMFSIP(string frequency, int day, int instalments, double amount, string status, string sipId) throws KiteException, IOException, JSONException {
        Map<string, Object> params = new HashMap<string, Object>();
        params.put("frequency", frequency);
        params.put("day", day);
        params.put("instalments", instalments);
        params.put("amount", amount);
        params.put("status", status);

        kiteRequestHandler.putRequest(routes.get("mutualfunds.sips.modify").replace(":sip_id", sipId), params, apiKey, accessToken);
        return true;
    }

    /** Cancel a mutualfunds sip.
     * @param sipId is the id of mutualfunds sip.
     * @return returns true, if cancel sip is successful else exception is thrown.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    boolean cancelMFSIP(string sipId) throws KiteException, IOException, JSONException {
        kiteRequestHandler.deleteRequest(routes.get("mutualfunds.sip").replace(":sip_id", sipId), new HashMap<string, Object>(), apiKey, accessToken);
        return true;
    }

    /** Retrieve all mutualfunds sip.
     * @return List of sips.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    List<MFSIP> getMFSIPs() throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("mutualfunds.sips"), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), MFSIP[].class));
    }

    /** Retrieve an individual sip.
     * @param sipId is the id of a particular sip.
     * @return MFSIP object which contains all the details of the sip.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    MFSIP getMFSIP(string sipId) throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("mutualfunds.sip").replace(":sip_id", sipId), apiKey, accessToken);
        return gson.fromJson(response.get("data").tostring(), MFSIP.class);
    }

    /** Retrieve all the mutualfunds holdings.
     * @return List of mutualfunds holdings.
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     * */
    List<MFHolding> getMFHoldings() throws KiteException, IOException, JSONException {
        JSONObject response = kiteRequestHandler.getRequest(routes.get("mutualfunds.holdings"), apiKey, accessToken);
        return Arrays.asList(gson.fromJson(string.valueOf(response.get("data")), MFHolding[].class));
    }
    /**
     * Logs out user by invalidating the access token.
     * @return JSONObject which contains status
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     */
    JSONObject logout() throws KiteException, IOException, JSONException {
        return invalidateAccessToken();
    }

    /**
     * Kills the session by invalidating the access token.
     * @return JSONObject which contains status
     * @throws KiteException is thrown for all Kite trade related errors.
     * @throws IOException is thrown when there is connection related error.
     */
    JSONObject invalidateAccessToken() throws IOException, KiteException, JSONException {
        string url = routes.get("api.token");
        Map<string, Object> params = new HashMap<>();
        params.put("api_key", apiKey);
        params.put("access_token", accessToken);
        return kiteRequestHandler.deleteRequest(url, params, apiKey, accessToken);
    }

    /**
     * Kills the refresh token.
     * @return JSONObject contains status.
     * @param refreshToken is the token received after successful log in.
     * @throws IOException is thrown for connection related errors.
     * @throws KiteException is thrown for Kite trade related errors.
     * */
    JSONObject invalidateRefreshToken(string refreshToken) throws IOException, KiteException, JSONException {
        Map<string, Object> param = new HashMap<>();
        param.put("refresh_token", refreshToken);
        param.put("api_key", apiKey);
        string url = routes.get("api.token");
        return kiteRequestHandler.deleteRequest(url, param, apiKey, accessToken);
    }

    /**This method parses csv and returns instrument list.
     * @param input is csv string.
     * @return  returns list of instruments.
     * @throws IOException is thrown when there is connection related error.
     * */
    private List<Instrument> readCSV(string input) throws IOException {
        ICsvBeanReader beanReader = null;
        File temp = File.createTempFile("tempfile", ".tmp");
        BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
        bw.write(input);
        bw.close();

        beanReader = new CsvBeanReader(new FileReader(temp), CsvPreference.STANDARD_PREFERENCE);
        string[] header = beanReader.getHeader(true);
        CellProcessor[] processors = getProcessors();
        Instrument instrument;
        List<Instrument> instruments = new ArrayList<>();
        while((instrument = beanReader.read(Instrument.class, header, processors)) != null ) {
            instruments.add(instrument);
        }
        return instruments;
    }

    /**This method parses csv and returns instrument list.
     * @param input is mutualfunds csv string.
     * @return  returns list of mutualfunds instruments.
     * @throws IOException is thrown when there is connection related error.
     * */
    private List<MFInstrument> readMfCSV(string input) throws IOException{
        ICsvBeanReader beanReader = null;
        File temp = File.createTempFile("tempfile", ".tmp");
        BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
        bw.write(input);
        bw.close();

        beanReader = new CsvBeanReader(new FileReader(temp), CsvPreference.STANDARD_PREFERENCE);
        string[] header = beanReader.getHeader(true);
        CellProcessor[] processors = getMfProcessors();
        MFInstrument instrument;
        List<MFInstrument> instruments = new ArrayList<>();
        while((instrument = beanReader.read(MFInstrument.class, header, processors)) != null ) {
            instruments.add(instrument);
        }
        return instruments;
    }

    /** This method returns array of cellprocessor for parsing csv.
     * @return CellProcessor[] array
     * */
    private CellProcessor[] getProcessors(){
        CellProcessor[] processors = new CellProcessor[]{
                new NotNull(new ParseLong()),   //instrument_token
                new NotNull(new ParseLong()),   //exchange_token
                new NotNull(),                  //trading_symbol
                new org.supercsv.cellprocessor.Optional(),                 //company name
                new NotNull(new ParseDouble()), //last_price
                new org.supercsv.cellprocessor.Optional(new ParseDate("yyyy-MM-dd")),                 //expiry
                new org.supercsv.cellprocessor.Optional(),                 //strike
                new NotNull(new ParseDouble()), //tick_size
                new NotNull(new ParseInt()),    //lot_size
                new NotNull(),                  //instrument_type
                new NotNull(),                  //segment
                new NotNull()                   //exchange
        };
        return processors;
    }

    /** This method returns array of cellprocessor for parsing mutual funds csv.
     * @return CellProcessor[] array
     * */
    private CellProcessor[] getMfProcessors(){
        CellProcessor[] processors = new CellProcessor[]{
                new org.supercsv.cellprocessor.Optional(),                  //tradingsymbol
                new org.supercsv.cellprocessor.Optional(),                  //amc
                new org.supercsv.cellprocessor.Optional(),                  //name
                new org.supercsv.cellprocessor.Optional(new ParseBool()),    //purchase_allowed
                new org.supercsv.cellprocessor.Optional(new ParseBool()),    //redemption_allowed
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //minimum_purchase_amount
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //purchase_amount_multiplier
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //minimum_additional_purchase_amount
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //minimum_redemption_quantity
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //redemption_quantity_multiplier
                new org.supercsv.cellprocessor.Optional(),                  //dividend_type
                new org.supercsv.cellprocessor.Optional(),                  //scheme_type
                new org.supercsv.cellprocessor.Optional(),                  //plan
                new org.supercsv.cellprocessor.Optional(),                  //settlement_type
                new org.supercsv.cellprocessor.Optional(new ParseDouble()), //last_price
                new org.supercsv.cellprocessor.Optional(new ParseDate("yyyy-MM-dd"))                   //last_price_date
        };
        return processors;
    }

}