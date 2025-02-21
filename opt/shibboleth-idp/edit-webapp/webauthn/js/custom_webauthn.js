/**
 *    * Convince cookie functions
 **/
function setCookie(cname, cvalue, exdays) {
        const d = new Date();
        d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
        let expires = "expires="+d.toUTCString();
        document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

function getCookie(cname) {
        let name = cname + "=";
        let ca = document.cookie.split(';');
        for(let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) == ' ') {
               c = c.substring(1);
            }
            if (c.indexOf(name) == 0) {
              return c.substring(name.length, c.length);
            }
        }
        return "";
}



function rejectIfNotSuccess(response) {
  if (response.success) {
    return response;
  } else {
    return new Promise((resolve, reject) => reject(response));
  }
}

function rejected(err) {
  return new Promise((resolve, reject) => reject(err));
}

function submitResponse(requestId, response) {
  const body = {
    requestId,
    credential: response,
  };

  document.getElementById("webauthnformdata").setAttribute("value", JSON.stringify(body));
  document.getElementById("webauthnform").submit();
}

function performCeremony(params) {
  const getRequest = params.getRequest; /* function(urls: object): { publicKeyCredentialCreationOptions: object } | { publicKeyCredentialRequestOptions: object } */
  const executeRequest = params.executeRequest; /* function({ publicKeyCredentialCreationOptions: object } | { publicKeyCredentialRequestOptions: object }): Promise[PublicKeyCredential] */
  const handleError = params.handleError; /* function(err): ? */

  return getRequest()
    .then((params) => {
      const request = params.request;
      return executeRequest(request)
        .then(webauthn.responseToObject)
        .then(response => ({
          request,
          response,
        }));
    })

    .then((params) => {
      const request = params.request;
      const response = params.response;
      return submitResponse(request.requestId, response);
    })
  ;
}

function getAuthenticateRequest(username) {
  return fetch("/idp/webauthn/registration?type=authstart", {
    body: new URLSearchParams(username ? { username } : {}),
    method: 'POST',
  })
    .then(response => response.json())
    .then(rejectIfNotSuccess)
  ;
}

function executeAuthenticateRequest(request) {
  return webauthn.getAssertion(request.publicKeyCredentialRequestOptions);
}

function authenticate(username = null, getRequest = getAuthenticateRequest) {
  return performCeremony({
    getRequest: urls => getRequest(username),
    executeRequest: executeAuthenticateRequest,
  }).catch((err) => {
    return rejected(err);
  });
}
