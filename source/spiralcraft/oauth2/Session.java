//
//Copyright (c) 2012 Michael Toth
//Spiralcraft Inc., All Rights Reserved
//
//This package is part of the Spiralcraft project and is licensed under
//a multiple-license framework.
//
//You may not use this file except in compliance with the terms found in the
//SPIRALCRAFT-LICENSE.txt file at the top of this distribution, or available
//at http://www.spiralcraft.org/licensing/SPIRALCRAFT-LICENSE.txt.
//
//Unless otherwise agreed to in writing, this software is distributed on an
//"AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or implied.
//
package spiralcraft.oauth2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

import spiralcraft.util.RandomUtil;
import spiralcraft.util.URIUtil;
import spiralcraft.util.string.StringUtil;

import spiralcraft.vfs.url.URLAccessException;
import spiralcraft.vfs.url.URLMessage;
import spiralcraft.vfs.util.ByteArrayResource;
import spiralcraft.log.ClassLog;
import spiralcraft.log.Level;
import spiralcraft.net.http.VariableMap;
import spiralcraft.net.http.client.Response;
import spiralcraft.net.mime.GenericHeader;
import spiralcraft.net.mime.MimeHeader;
import spiralcraft.net.mime.MimeHeaderMap;
import spiralcraft.text.ParseException;

public class Session
{

  protected static final ClassLog log
    =ClassLog.getInstance(Session.class);
 
  private static final Charset ASCII=Charset.forName("ASCII");
  
  @SuppressWarnings("unused")
  protected final Client client;
  private String oauthToken;
  @SuppressWarnings("unused")
  private String oauthTokenSecret;
  private boolean temporary;
  private URI returnURI;
  protected String oauthId;
  protected Level logLevel=Level.FINE;
  private String problem;
  protected String state=RandomUtil.generateString(20);
  
  protected Session(Client client)
  { 
    this.client=client;
    this.logLevel=client.logLevel;
  }
  
  public void setReturnURI(URI returnURI)
  { this.returnURI=returnURI;
  }
  
  public URI getReturnURI()
  { return returnURI;
  }
  
  /**
   * The unique and persistent id associated with the server account that this 
   *   session is authenticated with, if any. This may be the end user's own 
   *   user id on the server, or it may be the id of the resource owner.
   * 
   * @return
   */
  public String getOauthId()
  { return oauthId;
  }
  
  
  
  public boolean isTokenValid()
  { 
    // Incorp timeout
    return oauthToken!=null && !temporary;
  }
  
  /**
   * Obtain a set of temporary credentials from the server and return the
   *   URI where the user must authenticate themselves and authorize the
   *   request.
   * @throws IOException 
   * @throws MalformedURLException 
   */
  public URI startAuthSequence(URI callbackURI) 
    throws IOException,GeneralSecurityException
  {
    problem=null;
    temporary=true;
    VariableMap credentialRequestParams
      =makeCredentialRequestParameters(callbackURI);
      
//    credentialRequestParams.add
//      ("oauth_signature"
//      ,Signer.signHMAC_SHA1
//        (Signer.signatureBase
//          (client.credentialRequestVerb
//          ,client.getCredentialRequestURI()
//          ,credentialRequestParams
//          ,null
//          )
//        ,client.sharedSecret
//        ,null
//        )
//      );
    URI credentialRequestURI=client.getCredentialRequestURI();
    URI fullCredentialRequest
      =URIUtil.addRawQueryParams
        (credentialRequestURI
        ,credentialRequestParams.generateEncodedForm()
        );
    return fullCredentialRequest;
  }
  
  public String getProblem()
  { return problem;
  }
  
  public void abortAuthSequence(String failureCode)
  { this.problem=failureCode;
  }
  
  /**
   * Completes the auth sequence by requesting a set of token credentials
   * 
   * @param authCode
   * @param oauthVerifier
   */
  public void completeAuthSequence(String authCode,String oauthVerifier,URI redirectURI)
    throws IOException,GeneralSecurityException
  {
    if (!temporary)
    { 
      throw new GeneralSecurityException
        ("Authentication sequence already completed"
        );
      
    }
    
    if (authCode==null || oauthVerifier==null)
    {
      throw new GeneralSecurityException
        ("Missing OAuth token and/or verifier"
        );
    }
    
    if (!oauthVerifier.equals(state))
    { 
      throw new GeneralSecurityException
        ("'state' token does not match that sent to provider. Possible CSRF. "
        +oauthVerifier+"!="+state
        );
    }
    
    

    VariableMap tokenRequestParams
      =makeTokenRequestParameters(authCode,redirectURI);
    byte[] encodedTokenRequest
      =StringUtil.asciiBytes(tokenRequestParams.generateEncodedForm());
    log.fine("Calling "+client.tokenRequestURI+" with "+tokenRequestParams);
    // Call credentialRequestURI
    spiralcraft.net.http.client.Client httpClient
      =new spiralcraft.net.http.client.Client();
    Response response=
      httpClient.executeRequest
        ("POST"
        ,client.tokenRequestURI
        ,"application/x-www-form-urlencoded"
        ,new ByteArrayResource(encodedTokenRequest)
        );
    log.fine("Access Token Response "+response.toString());
    try
    {
      AccessTokenResponse accessTokenResponse
          =AccessTokenResponse.fromJSON(response.getContentAsString());
      log.fine("From json "+accessTokenResponse);
      temporary=false;
      this.oauthToken=accessTokenResponse.accessToken;
      
          
    }
    catch (ParseException x)
    { throw new IOException("Error reading JSON response",x);
    }
    
    
//    HttpURLConnection connection
//      =(HttpURLConnection) 
//         new URL(client.tokenRequestURI.toString()).openConnection();
//    log.fine(new String(encodedTokenRequest));
//    connection.setRequestMethod(client.tokenRequestVerb);
//    connection.addRequestProperty("Content-Length",Integer.toString(encodedTokenRequest.length));
//    connection.addRequestProperty("Content-Type","application/x-www-form-urlencoded");
//    connection.setDoInput(true);
//    connection.setDoOutput(true);
//    connection.addRequestProperty("Connection","close");
//    connection.setUseCaches(false);
////    String oauthHeader=oauthHeader(tokenRequestParams);
////    if (logLevel.isFine())
////    { log.fine("oauthHeader: "+oauthHeader);
////    }
////    connection.addRequestProperty
////      ("Authorization"
////      ,oauthHeader
////      );
//    connection.connect();
//    try
//    {
//      OutputStream out=connection.getOutputStream();
//      out.write(encodedTokenRequest);
//      out.flush();
//      out.close();
//      InputStream in=connection.getInputStream();
//      byte[] bytes=StreamUtil.readBytes(in,connection.getContentLength());
//      in.close();
//      String ret=new String(bytes);
//      log.fine(ret);
//    
//      if (logLevel.isFine())
//      { log.fine(ret);
//      }
//    
//      //XXX READ JSON HERE
//      //
//      // 
//      //XXX
//      
//      temporary=false;
//    }
//    catch (IOException x)
//    { 
//      InputStream errorStream
//        =connection.getErrorStream();
//      if (errorStream!=null)
//      { 
//        try
//        {
//          throw new URLAccessException
//            ("Connection returned remote error"
//            ,x
//            ,new URLMessage
//              (errorStream
//              ,connection.getContentLength()
//              ,connection.getHeaderFields()
//              )
//            );
//        }
//        finally
//        { 
//          errorStream.close();
//          connection.disconnect();
//        }
//         
//      }
//      else
//      { throw x;
//      }
//      
//    }
//    finally
//    { connection.disconnect();
//    }
    
    postAuthenticate();
    
  }
  

  /**
   * <p>Perform any actions required after successfully authenticating, such
   *   as populating the principalId property.
   * </p>
   * 
   * @throws IOException
   * @throws GeneralSecurityException
   */
  protected void postAuthenticate()
    throws IOException,GeneralSecurityException
  {
  }
  
  VariableMap makeRequestParameters()
  {
    VariableMap map=new VariableMap();

    map.set("client_id",client.clientId);
    return map;
  }
  
  VariableMap makeCredentialRequestParameters(URI redirectURI)
  {
    if (redirectURI==null)
    { redirectURI=client.redirectURI;
    }
    
    VariableMap map=makeRequestParameters();
    map.set("response_type","code");
    if (redirectURI!=null)
    { map.set("redirect_uri",redirectURI.toString());
    }
    map.set("state",state);
    return map;
  }
  
  VariableMap makeTokenRequestParameters(String oauthCode,URI redirectURI)
  {
    VariableMap map=new VariableMap();
    if (redirectURI==null)
    { redirectURI=client.redirectURI;
    }
    map.set("grant_type", "authorization_code");
    map.set("code",oauthCode);
    map.set("client_id",client.clientId);
    map.set("redirect_uri",redirectURI.toString());
    map.set("client_secret", client.sharedSecret);
    return map;
  }
  
  VariableMap makeResourceRequestParameters()
  {
    VariableMap map=makeRequestParameters();
    return map;
  }
  
  MimeHeader oauthHeader()
    throws IOException
  { return new GenericHeader("Authorization","Bearer "+this.oauthToken);
  }
  

//  String signedResourceRequestHeader(String verb,URI uri,VariableMap requestBody)
//    throws IOException,GeneralSecurityException
//  {
//    VariableMap resourceRequestParams
//      =makeResourceRequestParameters();
//    
//    resourceRequestParams.add
//      ("oauth_signature"
//      ,Signer.signHMAC_SHA1
//        (Signer.signatureBase
//          (verb
//          ,uri
//          ,resourceRequestParams
//          ,requestBody
//          )
//        ,client.sharedSecret
//        ,oauthTokenSecret
//        )
//      );
//    return oauthHeader(resourceRequestParams);
//  }
  
  public InputStream call(String verb,URI uri,VariableMap requestBody)
    throws IOException
  { 
      MimeHeader header=oauthHeader();
      MimeHeaderMap headerMap=new MimeHeaderMap();
      headerMap.add(header);
      spiralcraft.net.http.client.Client httpClient
        =new spiralcraft.net.http.client.Client();
      
      Response response=
        httpClient.executeRequest
          (verb
          ,uri
          ,verb.equals("POST")?"application/x-www-form-urlencoded":null
          ,requestBody!=null
            ?new ByteArrayResource(StringUtil.asciiBytes(requestBody.generateEncodedForm()))
            :null
          ,headerMap
          );
      if (response.getStatus()>400)
      {           
        throw new URLAccessException
          ("Connection returned remote error"
          ,null
          ,new URLMessage
            (response.getContent().getInputStream()
            ,Long.valueOf(response.getContentLength()).intValue()
            ,response.getHeaders().toStringListMap()
            )
          );

      }
      return response.getContent().getInputStream();
      
//      HttpURLConnection connection
//        =(HttpURLConnection) 
//           new URL(uri.toString()).openConnection();
//      connection.setRequestMethod(verb);
//      if (logLevel.isFine())
//      { log.fine("header for "+uri+": "+header);
//      }
//      connection.addRequestProperty
//        ("Authorization"
//        ,header
//        );
//      connection.setDoInput(true);
//      if (verb.equals("POST"))
//      { 
//        connection.setDoOutput(true);
//        connection.setRequestProperty
//          ("Content-Type","application/x-www-form-urlencoded");
//        connection.connect();
//        
//        String requestBodyEncoded
//          =requestBody!=null?requestBody.generateEncodedForm():"";
//        connection.setRequestProperty
//          ("Content-Length",Integer.toString(requestBodyEncoded.length()));
//        
//        OutputStream out=connection.getOutputStream();
//        out.write(requestBodyEncoded.getBytes(ASCII));
//        out.flush();
//        out.close();
//      }
//      else
//      { connection.connect();
//      }
//      
//      try
//      {
//        int contentLength=connection.getContentLength();
//        return new URLMessage
//          (connection.getInputStream()
//          ,contentLength
//          ,connection.getHeaderFields()
//          );
//      }
//      catch (IOException x)
//      {
//        InputStream errorStream
//          =connection.getErrorStream();
//        if (errorStream!=null)
//        { 
//          try
//          {
//            throw new URLAccessException
//              ("Connection returned remote error"
//              ,x
//              ,new URLMessage
//                (errorStream
//                ,connection.getContentLength()
//                ,connection.getHeaderFields()
//                )
//              );
//          }
//          finally
//          { 
//            errorStream.close();
//            connection.disconnect();
//          }
//          
//        }
//        else
//        { throw x;
//        }
//        
//      }
////    }
////    catch (GeneralSecurityException x)
////    { throw new IOException("Error signing request",x);
////    }
    
  }
  
  
  public void invalidate()
    throws IOException
  { 
    call("GET",client.tokenInvalidateURI,null);
    clear();
  }
  
  public void clear()
  {
    oauthToken=null;
    oauthTokenSecret=null;
    temporary=false;
    returnURI=null;
    problem=null;
  }
}