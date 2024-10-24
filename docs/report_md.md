# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 6 |
| Low | 9 |
| Informational | 9 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| CSP: Wildcard Directive | Medium | 2 |
| Content Security Policy (CSP) Header Not Set | Medium | 4 |
| Missing Anti-clickjacking Header | Medium | 4 |
| Secure Pages Include Mixed Content (Including Scripts) | Medium | 4 |
| Sub Resource Integrity Attribute Missing | Medium | 12 |
| Vulnerable JS Library | Medium | 1 |
| Cookie Without Secure Flag | Low | 2 |
| Cookie without SameSite Attribute | Low | 2 |
| Cross-Domain JavaScript Source File Inclusion | Low | 9 |
| HTTPS Content Available via HTTP | Low | 6 |
| Permissions Policy Header Not Set | Low | 8 |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 10 |
| Strict-Transport-Security Header Not Set | Low | 9 |
| Timestamp Disclosure - Unix | Low | 12 |
| X-Content-Type-Options Header Missing | Low | 7 |
| Authentication Request Identified | Informational | 1 |
| Cookie Slack Detector | Informational | 28 |
| Information Disclosure - Suspicious Comments | Informational | 3 |
| Non-Storable Content | Informational | 4 |
| Re-examine Cache-control Directives | Informational | 4 |
| Session Management Response Identified | Informational | 4 |
| Storable and Cacheable Content | Informational | 5 |
| Storable but Non-Cacheable Content | Informational | 1 |
| User Agent Fuzzer | Informational | 239 |




## Alert Detail



### [ CSP: Wildcard Directive ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined:
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'none'`
  * Other Info: `The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined:
frame-ancestors, form-action

The directive(s): frame-ancestors, form-action are among the directives that do not fallback to default-src, missing/excluding them is the same as allowing anything.`

Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources ](https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 4

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Secure Pages Include Mixed Content (Including Scripts) ](https://www.zaproxy.org/docs/alerts/10040/)



##### Medium (Medium)

### Description

The page includes mixed content, that is content accessed via HTTP instead of HTTPS.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Other Info: `tag=script src=http://html5shim.googlecode.com/svn/trunk/html5.js
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Other Info: `tag=script src=http://html5shim.googlecode.com/svn/trunk/html5.js
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Other Info: `tag=script src=http://html5shim.googlecode.com/svn/trunk/html5.js
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Other Info: `tag=script src=http://html5shim.googlecode.com/svn/trunk/html5.js
`

Instances: 4

### Solution

A page that is available over SSL/TLS must be comprised completely of content which is transmitted over SSL/TLS.
The page must not contain any content that is transmitted over unencrypted HTTP.
This includes content from third party sites.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)


#### CWE Id: [ 311 ](https://cwe.mitre.org/data/definitions/311.html)


#### WASC Id: 4

#### Source ID: 3

### [ Sub Resource Integrity Attribute Missing ](https://www.zaproxy.org/docs/alerts/90003/)



##### Medium (High)

### Description

The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link id="bootstrap_styles" rel="stylesheet"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css"/>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link id="bootstrap_styles" rel="stylesheet"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css"/>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link id="bootstrap_styles" rel="stylesheet"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" type="text/css"/>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``

Instances: 12

### Solution

Provide a valid integrity attribute to the tag.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity ](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)


#### CWE Id: [ 345 ](https://cwe.mitre.org/data/definitions/345.html)


#### WASC Id: 15

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library jquery, version 3.2.1 is vulnerable.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `jquery-3.2.1.min.js`
  * Other Info: `CVE-2020-11023
CVE-2020-11022
CVE-2019-11358
`

Instances: 1

### Solution

Please upgrade to the latest version of jquery.

### Reference


* [ https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ ](https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/)
* [ https://nvd.nist.gov/vuln/detail/CVE-2019-11358 ](https://nvd.nist.gov/vuln/detail/CVE-2019-11358)
* [ https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b ](https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b)
* [ https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/ ](https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/)


#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### Source ID: 3

### [ Cookie Without Secure Flag ](https://www.zaproxy.org/docs/alerts/10011/)



##### Low (Medium)

### Description

A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `Set-Cookie: connect.sid`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `Set-Cookie: connect.sid`
  * Other Info: ``

Instances: 2

### Solution

Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html)


#### CWE Id: [ 614 ](https://cwe.mitre.org/data/definitions/614.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cookie without SameSite Attribute ](https://www.zaproxy.org/docs/alerts/10054/)



##### Low (Medium)

### Description

A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `Set-Cookie: connect.sid`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `Set-Cookie: connect.sid`
  * Other Info: ``

Instances: 2

### Solution

Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

### Reference


* [ https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site ](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site)


#### CWE Id: [ 1275 ](https://cwe.mitre.org/data/definitions/1275.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `http://html5shim.googlecode.com/svn/trunk/html5.js`
  * Attack: ``
  * Evidence: `<script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript"
        src="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.3/js/bootstrapValidator.js"></script>`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js`
  * Attack: ``
  * Evidence: `<script type="text/javascript" src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>`
  * Other Info: ``

Instances: 9

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ HTTPS Content Available via HTTP ](https://www.zaproxy.org/docs/alerts/10047/)



##### Low (Medium)

### Description

Content which was initially accessed via HTTPS (i.e.: using SSL/TLS encryption) is also accessible via HTTP (without encryption).

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/login`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/login`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://log8100-10-dev-2addd04e4cb7.herokuapp.com/register`
  * Other Info: `ZAP attempted to connect via: http://log8100-10-dev-2addd04e4cb7.herokuapp.com/register`

Instances: 6

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to only serve such content via HTTPS. Consider implementing HTTP Strict Transport Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ https://caniuse.com/stricttransportsecurity ](https://caniuse.com/stricttransportsecurity)
* [ https://datatracker.ietf.org/doc/html/rfc6797 ](https://datatracker.ietf.org/doc/html/rfc6797)


#### CWE Id: [ 311 ](https://cwe.mitre.org/data/definitions/311.html)


#### WASC Id: 4

#### Source ID: 1

### [ Permissions Policy Header Not Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 8

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
* [ https://developer.chrome.com/blog/feature-policy/ ](https://developer.chrome.com/blog/feature-policy/)
* [ https://scotthelme.co.uk/a-new-security-header-feature-policy/ ](https://scotthelme.co.uk/a-new-security-header-feature-policy/)
* [ https://w3c.github.io/webappsec-feature-policy/ ](https://w3c.github.io/webappsec-feature-policy/)
* [ https://www.smashingmagazine.com/2018/12/feature-policy/ ](https://www.smashingmagazine.com/2018/12/feature-policy/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) ](https://www.zaproxy.org/docs/alerts/10037/)



##### Low (Medium)

### Description

The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Express`
  * Other Info: ``

Instances: 10

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework ](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
* [ https://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html ](https://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Strict-Transport-Security Header Not Set ](https://www.zaproxy.org/docs/alerts/10035/)



##### Low (High)

### Description

HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 9

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ https://caniuse.com/stricttransportsecurity ](https://caniuse.com/stricttransportsecurity)
* [ https://datatracker.ietf.org/doc/html/rfc6797 ](https://datatracker.ietf.org/doc/html/rfc6797)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 15

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741934`
  * Other Info: `1729741934, which evaluates to: 2024-10-24 03:52:14.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741934`
  * Other Info: `1729741934, which evaluates to: 2024-10-24 03:52:14.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Reporting-Endpoints`
  * Attack: ``
  * Evidence: `1729741936`
  * Other Info: `1729741936, which evaluates to: 2024-10-24 03:52:16.`

Instances: 12

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: 7

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login`

Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Cookie Slack Detector ](https://www.zaproxy.org/docs/alerts/90027/)



##### Informational (Low)

### Description

Repeated GET requests: drop a different cookie each time, followed by normal request with all cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where cookie based authentication/attributes are not actually enforced.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [connect.sid] A follow-on request with all original cookies still had a different response than the original request.
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: connect.sid
`

Instances: 28

### Solution



### Reference


* [ https://cwe.mitre.org/data/definitions/205.html ](https://cwe.mitre.org/data/definitions/205.html)


#### CWE Id: [ 205 ](https://cwe.mitre.org/data/definitions/205.html)


#### WASC Id: 45

#### Source ID: 1

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `db`
  * Other Info: `The following pattern was used: \bDB\b and was detected 2 times, the first in the element starting with: "a.removeEventListener("load",S),r.ready()}"complete"===d.readyState||"loading"!==d.readyState&&!d.documentElement.doScroll?a.set", see evidence field for the suspicious comment/snippet.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/jquery-3.2.1.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `select`
  * Other Info: `The following pattern was used: \bSELECT\b and was detected in the element starting with: "!function(a,b){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=a.document?b(a,!0):function(", see evidence field for the suspicious comment/snippet.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/showdown.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `from`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in the element starting with: "(function(){function a(a){"use strict";var b={omitExtraWLInCodeBlocks:{defaultValue:!1,describe:"Omit the default extra whitelin", see evidence field for the suspicious comment/snippet.`

Instances: 3

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``

Instances: 4

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 4

### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AiQqTAaUQyQz7l1l2w56VzvDvCqVvNJaJ.pGgDiqnETygXPKLbReTq%2BLjtAwT932ZJUSHINn21POs`
  * Other Info: `
cookie:connect.sid`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3A_xU_AaLsX33FNHT69pqvEDvxjA9D2G6P.3fOkgbDyQI5xmK595puXRq06eX%2F4Hkn4tMAGoUH1%2FII`
  * Other Info: `
cookie:connect.sid`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3AiQqTAaUQyQz7l1l2w56VzvDvCqVvNJaJ.pGgDiqnETygXPKLbReTq%2BLjtAwT932ZJUSHINn21POs`
  * Other Info: `
cookie:connect.sid`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `connect.sid`
  * Attack: ``
  * Evidence: `s%3A_xU_AaLsX33FNHT69pqvEDvxjA9D2G6P.3fOkgbDyQI5xmK595puXRq06eX%2F4Hkn4tMAGoUH1%2FII`
  * Other Info: `
cookie:connect.sid`

Instances: 4

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id)



#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`

Instances: 5

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css/font-awesome.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``

Instances: 1

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/assets/fa/css
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a10_logging
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a1_injection
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a2_broken_auth
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a3_sensitive_data
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a4_xxe
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a5_broken_access_control
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a6_sec_misconf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a7_xss
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a8_ides
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/a9_vuln_component
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_csrf
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/learn/vulnerability/ax_redirect
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/logout
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/register
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/forgotpw
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: https://log8100-10-dev-2addd04e4cb7.herokuapp.com/login
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``

Instances: 239

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


