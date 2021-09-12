package burp;

import classfiles.customIssue;

import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;


public class BurpExtender implements IBurpExtender, IScannerCheck {
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;
    IRequestInfo requestInfo;
    List<String> requestString;
    byte[] base64;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // extension code goes here
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Dustin's First Burp Extension");

        callbacks.registerScannerCheck(this);

        callbacks.printOutput("Upload Completed");
    }

    /*****************************************************************************************
     *  findAuthorization(List<String> request, byte[] body)
     * Inputs: Application Request Header List, Body of Request Response
     * @return Returns the List positions for the matches found if the flag is in header
     *****************************************************************************************/
    private List<int[]> findAuthorization(List<String> request, byte[] body) {

        String authorization = "Authorization:";
        var wrapper = new Object(){ int start = 0; };
        List<int[]> matches = new ArrayList<int[]>();
        Pattern auth = Pattern.compile("(?<=Authorization: basic\s).*");

        //Loop through header request to check for flag match
        request.forEach((temp) -> {
            if (temp.contains(authorization)) {
                Matcher matcher = auth.matcher(temp);
                //Check if Authorization header is present
                if (matcher.find()) {
                    //Return the base64 encoded Authorization header in bytes
                    base64 = matcher.group().getBytes();
                    try {
                        byte[] base64bytes = Base64.getDecoder().decode(base64);

                        //Convert the header into a string and change to lowercase for more matches
                        String base64string = new String(base64bytes).toLowerCase();

                        Pattern pattern = Pattern.compile( "123flag123" , Pattern.CASE_INSENSITIVE);

                        matcher = pattern.matcher(base64string);
                        if(matcher.find()) {
                            //If the flag is found and can be decoded then add it to the matches list
                            wrapper.start = helpers.indexOf(body, base64, false, wrapper.start, body.length);
                            matches.add(new int[]{wrapper.start, wrapper.start + base64.length});
                        }

                    } catch (Exception e) {
                        callbacks.printError(String.format("Could Not Decode Header"));
                    }
                }
                else{
                    callbacks.printError("Authorization: Format Unknown");
                }
            }
        });
        //Return null if nothing was found
        return matches;
    }
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        //Return intercepted request
        requestInfo = helpers.analyzeRequest(baseRequestResponse);
        requestString = requestInfo.getHeaders();
        List<IScanIssue> issues = new ArrayList<>(1);

        if (callbacks.isInScope(requestInfo.getUrl())) {
            List<int[]> matches = findAuthorization(requestString, baseRequestResponse.getRequest());
            if (matches.size() > 0) {
                issues.add(new customIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) }, "FLAG 123 FOUND", "FLAG123FLAG", "Low"));
            }
            return issues;

        }else{
            callbacks.printOutput("Out of Scope!");
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
