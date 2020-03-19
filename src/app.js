// A simple token-based authorizer example to demonstrate how to use an authorization token 
// to allow or deny a request. In this example, the caller named 'user' is allowed to invoke 
// a request if the client-supplied token value is 'allow'. The caller is not allowed to invoke 
// the request if the token value is 'deny'. If the token value is 'unauthorized' or an empty
// string, the authorizer function returns an HTTP 401 status code. For any other token value, 
// the authorizer returns an HTTP 500 status code. 
// Note that token values are case-sensitive.

exports.handler =  function(event, context, callback) {
    console.log(event);
    console.log(context);
    var token = event.authorizationToken;
    console.log(token);
    const jwt = require('jsonwebtoken');
    try {
        var decoded = jwt.verify(token, '9825f17940e086bfd5c08a91030a8a7b');
        //兼容后端Lambda Functin
        //该Lambda Function认为验证是通过Cognito，代码中会通过claims来获取用户名等
        var claims = {
                "cognito:username": decoded.username
        }

        var expired = (Date.parse(new Date()) / 1000) > decoded.exp
        
      if (expired) {
        //过期
        console.log("Expired Token");
        callback("Error: Token Expired");
      }else {
        // 合法也没过期，正常放行
        console.log("Valid token.");
        callback(null, generatePolicy('user', 'Allow', event.methodArn, claims));
      }
    } catch (error) {
        console.log(error);
        callback("Error: Invalid token"); // Return a 500 Invalid token response
    }
};

// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource, claims) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true,
        //目前自定义的context不支持直接传入JSON Object，需要先stringify，并在Lambda中恢复后进行访问
        "claims" : JSON.stringify(claims) 
    };
    
    return authResponse;
}