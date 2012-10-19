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
package spiralcraft.oauth1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

import spiralcraft.time.Clock;
import spiralcraft.util.RandomUtil;
import spiralcraft.util.URIUtil;
import spiralcraft.vfs.StreamUtil;
import spiralcraft.vfs.url.URLAccessException;
import spiralcraft.vfs.url.URLMessage;
import spiralcraft.log.ClassLog;
import spiralcraft.log.Level;
import spiralcraft.net.http.VariableMap;

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
  protected Level logLevel;
  private String problem;
  
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
    
    credentialRequestParams.add
      ("oauth_signature"
      ,Signer.signHMAC_SHA1
        (Signer.signatureBase
          (client.credentialRequestVerb
          ,client.getCredentialRequestURI()
          ,credentialRequestParams
          ,null
          )
        ,client.sharedSecret
        ,null
        )
      );
    // Call credentialRequestURI
    HttpURLConnection connection
      =(HttpURLConnection) 
         new URL(client.getCredentialRequestURI().toString()).openConnection();
    
    connection.setRequestMethod(client.credentialRequestVerb);
    connection.addRequestProperty("Content-Length","0");
    connection.addRequestProperty("Content-Type","text/xml");
    connection.setDoInput(true);
    connection.setDoOutput(true);
    connection.addRequestProperty("Connection","close");
    connection.setUseCaches(false);
    String oauthHeader=oauthHeader(credentialRequestParams);
    if (logLevel.isFine())
    { log.fine("oauthHeader: "+oauthHeader);
    }
    connection.addRequestProperty
      ("Authorization"
      ,oauthHeader
      );
    connection.connect();
    try
    {
      OutputStream out=connection.getOutputStream();
      out.flush();
      out.close();
      InputStream in=connection.getInputStream();
      byte[] bytes=StreamUtil.readBytes(in,connection.getContentLength());
      in.close();
      String ret=new String(bytes);
      VariableMap resultProperties=VariableMap.fromUrlEncodedString(ret);
    
      if (logLevel.isFine())
      { log.fine(ret);
      }
    
      // Read x-form-urlencoded response body
      this.oauthToken=resultProperties.getFirst("oauth_token");
      this.oauthTokenSecret=resultProperties.getFirst("oauth_token_secret");
      temporary=true;
    
      return URIUtil.replaceRawQuery
        (client.authorizationURI,"oauth_token="+this.oauthToken);
    }
    catch (IOException x)
    { 
      InputStream errorStream
        =connection.getErrorStream();
      if (errorStream!=null)
      { 
        try
        {
          throw new URLAccessException
            ("Connection returned remote error"
            ,x
            ,new URLMessage
              (errorStream
              ,connection.getContentLength()
              ,connection.getHeaderFields()
              )
            );
        }
        finally
        { 
          errorStream.close();
          connection.disconnect();
        }
         
      }
      else
      { throw x;
      }
      
    }
    finally
    { connection.disconnect();
    }
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
   * @param oauthToken
   * @param oauthVerifier
   */
  public void completeAuthSequence(String oauthToken,String oauthVerifier)
    throws IOException,GeneralSecurityException
  {
    if (!temporary)
    { 
      throw new GeneralSecurityException
        ("Authentication sequence already completed"
        );
      
    }
    
    if (oauthToken==null || oauthVerifier==null)
    {
      throw new GeneralSecurityException
        ("Missing OAuth token and/or verifier"
        );
    }
    
    // Call the token request URI with the oauthVerifier
    if (!oauthToken.equals(this.oauthToken))
    { 
      throw new GeneralSecurityException
        ("Token "+oauthToken
        +" does not match the token for this oauth session ("+this.oauthToken+")"
        );
    }

    VariableMap tokenRequestParams
      =makeTokenRequestParameters(oauthVerifier);
    
    tokenRequestParams.add
      ("oauth_signature"
      ,Signer.signHMAC_SHA1
        (Signer.signatureBase
          (client.tokenRequestVerb
          ,client.tokenRequestURI
          ,tokenRequestParams
          ,null
          )
        ,client.sharedSecret
        ,oauthTokenSecret
        )
      );    
    
    // Call credentialRequestURI
    HttpURLConnection connection
      =(HttpURLConnection) 
         new URL(client.tokenRequestURI.toString()).openConnection();
    
    connection.setRequestMethod(client.tokenRequestVerb);
    connection.addRequestProperty("Content-Length","0");
    connection.addRequestProperty("Content-Type","text/xml");
    connection.setDoInput(true);
    connection.setDoOutput(true);
    connection.addRequestProperty("Connection","close");
    connection.setUseCaches(false);
    String oauthHeader=oauthHeader(tokenRequestParams);
    if (logLevel.isFine())
    { log.fine("oauthHeader: "+oauthHeader);
    }
    connection.addRequestProperty
      ("Authorization"
      ,oauthHeader
      );
    connection.connect();
    try
    {
      OutputStream out=connection.getOutputStream();
      out.flush();
      out.close();
      InputStream in=connection.getInputStream();
      byte[] bytes=StreamUtil.readBytes(in,connection.getContentLength());
      in.close();
      String ret=new String(bytes);
      VariableMap resultProperties=VariableMap.fromUrlEncodedString(ret);
    
      if (logLevel.isFine())
      { log.fine(ret);
      }
    
      // Read x-form-urlencoded response body
      this.oauthToken=resultProperties.getFirst("oauth_token");
      this.oauthTokenSecret=resultProperties.getFirst("oauth_token_secret");
      temporary=false;
    }
    catch (IOException x)
    { 
      InputStream errorStream
        =connection.getErrorStream();
      if (errorStream!=null)
      { 
        try
        {
          throw new URLAccessException
            ("Connection returned remote error"
            ,x
            ,new URLMessage
              (errorStream
              ,connection.getContentLength()
              ,connection.getHeaderFields()
              )
            );
        }
        finally
        { 
          errorStream.close();
          connection.disconnect();
        }
         
      }
      else
      { throw x;
      }
      
    }
    finally
    { connection.disconnect();
    }
    
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
    map.set
      ("oauth_timestamp"
      ,Long.toString(Clock.instance().approxTimeMillis()/1000)
      );
    map.set("oauth_consumer_key",client.clientId);
    map.set("oauth_version","1.0");
    map.set("oauth_signature_method","HMAC-SHA1");
    map.set("oauth_nonce",RandomUtil.generateString(10));
    return map;
  }
  
  VariableMap makeCredentialRequestParameters(URI callbackURI)
  {
    if (callbackURI==null)
    { callbackURI=client.callbackURI;
    }
    
    VariableMap map=makeRequestParameters();
    if (callbackURI!=null)
    { map.set("oauth_callback",callbackURI.toString());
    }
    return map;
  }
  
  VariableMap makeTokenRequestParameters(String oauthVerifier)
  {
    VariableMap map=makeRequestParameters();
    map.set("oauth_token",oauthToken);
    map.set("oauth_verifier",oauthVerifier);
    return map;
  }
  
  VariableMap makeResourceRequestParameters()
  {
    VariableMap map=makeRequestParameters();
    map.set("oauth_token",oauthToken);
    return map;
  }
  
  String oauthHeader(VariableMap oauthProperties)
    throws IOException
  {
    StringBuilder buf=new StringBuilder();
    buf.append("OAuth ");
    boolean first=true;
    
    if (client.realm!=null && !client.realm.isEmpty())
    { 
      buf.append("realm=\"");
      Signer.percentEncode(client.realm,buf);
      buf.append("\"");
      first=false;
    }
    for (String name: oauthProperties.keySet())
    { 
      if (first)
      { first=false;
      }
      else
      { buf.append(",");
      }
      buf.append(name);
      buf.append("=\"");
      Signer.percentEncode(oauthProperties.getFirst(name),buf);
      buf.append("\"");
    }
    return buf.toString();
  }
  

  String signedResourceRequestHeader(String verb,URI uri,VariableMap requestBody)
    throws IOException,GeneralSecurityException
  {
    VariableMap resourceRequestParams
      =makeResourceRequestParameters();
    
    resourceRequestParams.add
      ("oauth_signature"
      ,Signer.signHMAC_SHA1
        (Signer.signatureBase
          (verb
          ,uri
          ,resourceRequestParams
          ,requestBody
          )
        ,client.sharedSecret
        ,oauthTokenSecret
        )
      );
    return oauthHeader(resourceRequestParams);
  }
  
  public URLMessage call(String verb,URI uri,VariableMap requestBody)
    throws IOException
  { 
    try
    { 
      String header=signedResourceRequestHeader(verb,uri,requestBody);
      HttpURLConnection connection
        =(HttpURLConnection) 
           new URL(uri.toString()).openConnection();
      connection.setRequestMethod(verb);
      if (logLevel.isFine())
      { log.fine("header for "+uri+": "+header);
      }
      connection.addRequestProperty
        ("Authorization"
        ,header
        );
      connection.setDoInput(true);
      if (verb.equals("POST"))
      { 
        connection.setDoOutput(true);
        connection.setRequestProperty
          ("Content-Type","application/x-www-form-urlencoded");
        connection.connect();
        
        String requestBodyEncoded
          =requestBody!=null?requestBody.generateEncodedForm():"";
        connection.setRequestProperty
          ("Content-Length",Integer.toString(requestBodyEncoded.length()));
        
        OutputStream out=connection.getOutputStream();
        out.write(requestBodyEncoded.getBytes(ASCII));
        out.flush();
        out.close();
      }
      else
      { connection.connect();
      }
      
      try
      {
        int contentLength=connection.getContentLength();
        return new URLMessage
          (connection.getInputStream()
          ,contentLength
          ,connection.getHeaderFields()
          );
      }
      catch (IOException x)
      {
        InputStream errorStream
          =connection.getErrorStream();
        if (errorStream!=null)
        { 
          try
          {
            throw new URLAccessException
              ("Connection returned remote error"
              ,x
              ,new URLMessage
                (errorStream
                ,connection.getContentLength()
                ,connection.getHeaderFields()
                )
              );
          }
          finally
          { 
            errorStream.close();
            connection.disconnect();
          }
          
        }
        else
        { throw x;
        }
        
      }
    }
    catch (GeneralSecurityException x)
    { throw new IOException("Error signing request",x);
    }
    
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
