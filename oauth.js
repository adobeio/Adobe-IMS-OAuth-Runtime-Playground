function main(args) {
    let access = args.access;
    let refresh = args.refresh;
    let oauth_url = args.oauth_url;
    let callback_url = args.callback_url;

    let html = `<!DOCTYPE html>
    <html lang="en">
       <head>
          <meta charset="utf-8">
          <title>Adobe IMS OAuth Playground</title>
          <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
          <script>
             function showSecret() {
                 var x = document.getElementById("clientSecret");
                 if (x.type === "password") {
                     x.type = "text";
                 } else {
                     x.type = "password";
                 }
             }  
             
             
             function textCopy(id,alertId) {
                 $('.alert').hide();
             
                 var copyText = document.getElementById(id);
                 if (copyText.value != "") {
                     copyText.select();
                     document.execCommand("Copy");
                     $('.alert#'+alertId).text("Token copied successfully!").fadeTo(2000, 500).slideUp(500, function () {
                         $(".alert#"+alertId).slideUp(500);
                     });
                 }
             }
          </script>    
       </head>
       <body>
          <div class="container">
             <div class="row">
                <div class="container">
                   <h2><a href="${oauth_url}.html">Adobe IMS OAuth Playground</a></h2>
                   <p class="lead">Please use your <a href="https://console.adobe.io" target="_blank">Adobe I/O Console</a>
                      Credentials below to generate your OAuth Access
                      Token
                   </p>
                   <hr>
                </div>
             </div>
             <ul class="nav nav-tabs">
                <li class="active"><a data-toggle="tab" href="#auth">Authorization</a></li>
                <li><a data-toggle="tab" href="#tokens">Tokens</a></li>
                <li><a data-toggle="tab" href="#faqs">FAQs</a></li>
             </ul>
             <div class="tab-content">
                <div id="auth" class="tab-pane fade in active">
                   <div class="row">
                      <div class="container">
                         <h3>Step 1: I/O Console Credentials</h3>
                         <br>
                         <div class="alert alert-danger" id="1" hidden="true">
                         </div>
                         <form id="consoleCredentials" onsubmit="generate(); return false">
                            <div class="form-group">
                               <label for="authEndpoint">IMS OAuth Authorization Endpoint</label>
                               <input type="text" class="form-control" id="authEndpoint"
                                  value="https://ims-na1.adobelogin.com/ims/authorize/v1" readonly>
                               <small id="technicalAccountHelp" class="form-text text-muted">Adobe IMS OAuth Authorization
                               endpoint
                               [Production Environment]
                               </small>
                            </div>
                            <div class="form-group">
                               <label for="tokenEndpoint">IMS OAuth Token Endpoint</label>
                               <input type="text" class="form-control" id="tokenEndpoint"
                                  value="https://ims-na1.adobelogin.com/ims/token/v1" readonly>
                               <small id="orgIDHelp" class="form-text text-muted">Adobe IMS OAuth Token endpoint
                               [Production
                               Environment]
                               </small>
                            </div>
                            <div class="form-group">
                               <label for="clientID">API Key (Client ID)</label>
                               <input type="text" class="form-control" id="clientID" placeholder="Enter Client ID" required>
                               <small id="clientIDHelp" class="form-text text-muted">console.adobe.io -> "Integration" ->
                               "Overview" -> "Client Credentials" -> "API Key (Client ID)" on your Adobe I/O Console
                               Integration
                               </small>
                            </div>
                            <div class="form-group">
                               <label for="clientSecret">Client Secret</label>
                               <input type="password" class="form-control" id="clientSecret" placeholder="Enter Client Secret" required>
                               <small id="clientSecretHelp" class="form-text text-muted">console.adobe.io -> "Integration"
                               ->
                               "Overview" -> "Client Credentials" -> "Client secret" on your Adobe I/O Console
                               Integration
                               </small>
                               <p></p>
                               <div><a class="btn btn-default btn-sm" onclick="showSecret()"><span
                                  class="glyphicon glyphicon-eye-open"></span> Show Secret</a></div>
                            </div>
                            <div class="form-group">
                               <label for="scope">Scopes</label>
                               <input type="text" class="form-control" id="scope" value="openid,creative_sdk"
                                  required>
                               <small id="tenantHelp" class="form-text text-muted">Refer to FAQ page to learn more about scopes
                               </small>
                            </div>
                            <br>
                            <button type="submit" class="btn btn-primary">Generate Tokens
                            </button>
                            <br>
                         </form>
                      </div>
                   </div>
                </div>
                <div id="tokens" class="tab-pane fade">
                   <div class="row">
                      <div class="container">
                         <h3>Step 2: Tokens</h3>
                         <br>
                         <div class="alert alert-success" id="3" hidden="true">
                         </div>
                         <div class="form-group">
                            <label for="accessToken">Access Token</label>
                            <textarea readonly rows="10" class="form-control" id="accessToken"
                               placeholder="Your access token will arrive here"></textarea>
                            <p></p>
                            <div><a class="btn btn-default btn-sm" onclick="textCopy('accessToken',3)">Copy</a></div>
                         </div>
                         <div class="form-group">
                            <label for="refreshToken">Refresh Token</label>
                            <textarea readonly rows="10" class="form-control" id="refreshToken"
                               placeholder="Your refresh token will arrive here"></textarea>
                            <p></p>
                            <div><a class="btn btn-default btn-sm" onclick="textCopy('refreshToken',3)">Copy</a></div>
                         </div>
                      </div>
                   </div>
                </div>
                <div id="faqs" class="tab-pane fade">
                   <div class="row">
                      <div class="container">
                         <h3>Frequently Asked Questions</h3>
                         <br>
                         <div class="form-group">
                            <p><strong>Q: How to use this application?</strong></p>
                            <p>A: I/O Console Integration
                            <ol>
                               <li>Go to <a href="https://console.adobe.io" target="_blank">Adobe I/O Console</a></li>
                               <li>Create an integration-> Select Access an API-> Select services you wish to integrate with (e.g. Adobe Stock->OAuth Integration)</li>
                               <li>Provide the Default redirect URI as ${callback_url}</li>
                               <li>Go to ${oauth_url}.html</li>
                            </ol>
                            </p>
                            <br>
                            <p><strong>Q: Who should be using application?</strong></p>
                            <p>A: Anyone who has created an integration at <a href="https://console.adobe.io/" target="_blank">Adobe I/O Console</a> with integration type OAuth and trying to retrieve an OAuth access token</p>
                            <br>
                            <p><strong>Q: Can I see the code?</strong></p>
                            <p>A: Absolutely, the application is created to provide sample code to interact with Adobe IMS OAuth endpoints. You can find the repositories here:
                            <table class="table table-condensed">
                               <tr>
                                  <td>1. I/O Runtime (OpenWhisk) Actions</td>
                                  <td><a href="https://git.corp.adobe.com/hireshah/Adobe-IMS-OAuth-Runtime-Playground" target="_blank">Adobe-IMS-OAuth-Runtime-Playground</a></p></td>
                               </tr>
                               <tr>
                                  <td>2. Node JS Application using Passport JS and passport-adobe-oauth2 strategy</td>
                                  <td><a href="https://git.corp.adobe.com/hireshah/Adobe-IMS-OAuth-Playground" target="_blank">Adobe-IMS-OAuth-Playground</a></p></td>
                               </tr>
                               <tr>
                                  <td>3. Simple Node JS Application</td>
                                  <td><a href="https://git.corp.adobe.com/hireshah/Adobe-IMS-Node-Playground" target="_blank">Adobe-IMS-OAuth-Node-Playground</a></p></td>
                               </tr>
                            </table>
                            <br>
                            <p><strong>Q: Where I can find the latest information on Scopes, Authorization and Access Endpoint URLs?</strong></p>
                            <p>A: To provide you the latest and relevant information about scopes, endpoint URLs and other important stuff, we are maintaining a resources page on github: <a href="https://git.corp.adobe.com/hireshah/Adobe-IMS-OAuth-Playground/blob/master/Resources.md" target="_blank">Resources</a></p>
                            <br>
                            <p><strong>Q: Who built this?</strong></p>
                            <p>A: <a href="https://www.adobe.io/">Adobe I/O</a> Solutions team</p>
                            <br>
                            <p><strong>Useful links:</strong></p>
                            <ul>
                               <li><a href="https://github.com/adobeio" target="_blank">Our Github repositories</a></li>
                               <li><a href="https://www.adobe.io/apis/cloudplatform/console/authentication/gettingstarted.html" target="_blank">Adobe I/O Authentication Overview</a></li>
                               <li><a href="http://www.passportjs.org/docs/oauth/" target="_blank">Learn more about Passport OAuth</a></li>
                            </ul>
                            <br>
                         </div>
                      </div>
                   </div>
                </div>
             </div>
          </div>
          <script src="//code.jquery.com/jquery-2.2.4.min.js" integrity="sha256-BbhdlvQf/xTY9gja0Dq3HiwQF8LaCRTXxZKRutelT44="
             crossorigin="anonymous"></script>
          <script>
             function generate() {
                 $('.alert').hide();
             
                 var authEndpoint = $("input#authEndpoint").val();
                 var clientID = $("input#clientID").val();
                 var scope = $("input#scope").val();
                 var tokenEndpoint = $("input#tokenEndpoint").val();
                 var clientSecret = $("input#clientSecret").val();
             
                 var cookie={
                     auth_provider:'adobe',
                     client_id:clientID,
                     client_secret:clientSecret,
                     scopes:scope
                 };
             
                 window.open("${callback_url}?auth_provider=adobe&client_id="+clientID+"&client_secret="+clientSecret+"&scopes="+scope,"_self");
             
             
             
                 
             }
          </script>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.loadtemplate/1.5.10/jquery.loadTemplate.min.js" integrity="sha256-mF3k3rmuuGVi/6GhJ5atwMd7JsTsQhULB6GyLaFPrMU=" crossorigin="anonymous"></script>
          <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
          <script>
             var access='${access}';
             var refresh='${refresh}';
             if(access!=='undefined')
                 {
                     $('a[href="#tokens"]').click();
                     $("#accessToken").text(access);
                     $("#refreshToken").text(refresh);
                     $(".alert#3").text("Tokens generated successfully!").fadeTo(2000, 500).slideUp(500, function () {
                         $(".alert#3").slideUp(500);
                     });                        
                 }
          </script>
       </body>
    </html>`

    return {html: html}


}
