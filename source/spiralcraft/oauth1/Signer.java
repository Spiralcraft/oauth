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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import spiralcraft.codec.text.Base64Codec;
import spiralcraft.log.ClassLog;
import spiralcraft.net.http.VariableMap;

public class Signer
{
  private static final ClassLog log=ClassLog.getInstance(Signer.class);
  private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  
  
  public static final String signHMAC_SHA1
    (String base,String clientSecret,String tokenSecret) 
    throws GeneralSecurityException
  {
    log.fine("Signing: "+base);
    String key
      =(clientSecret!=null?percentEncode(clientSecret):"")
      +"&"
      +(tokenSecret!=null?percentEncode(tokenSecret):"")
      ;
    
    SecretKeySpec signingKey 
      = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    mac.init(signingKey);

    try
    {
      byte[] hmac = mac.doFinal(base.getBytes("ASCII"));
      return Base64Codec.encodeBytes(hmac);
    }
    catch (UnsupportedEncodingException x)
    { throw new RuntimeException(x);
    }

  }
  
  public static final String signatureBase
    (String method
    ,URI requestURI
    ,VariableMap oauthParams
    ,VariableMap requestBody
    )
    throws IOException
  {
    StringBuilder buf
      =new StringBuilder();
    buf.append(method.toUpperCase());
    buf.append("&");
    Signer.encodeBaseStringURI(requestURI,buf);
    buf.append("&");
    Signer.encodeParameters(requestURI,oauthParams,requestBody,buf);
    return buf.toString();
  }

  public static final void encodeBaseStringURI(URI requestURI,Appendable buf)
    throws IOException
  { 
    StringBuilder temp=new StringBuilder();
    // TODO: Make sure port is excluded/included according to spec
    temp.append(requestURI.getScheme().toLowerCase())
      .append("://")
      .append(requestURI.getAuthority().toLowerCase())
      .append(requestURI.getRawPath());
    percentEncode(temp.toString(),buf);
  }
  
  public static final void encodeParameters
    (URI requestURI
    ,VariableMap oauthParams
    ,VariableMap requestBody
    ,Appendable buf
    )
    throws IOException
  {
    StringBuilder temp=new StringBuilder();
    ArrayList<Pair> encodedParameters=new ArrayList<Pair>();
    if (requestURI.getQuery()!=null)
    { 
      VariableMap query
        =VariableMap.fromUrlEncodedString(requestURI.getRawQuery());
      encodeParameterSet(query,encodedParameters);
    }
    if (oauthParams!=null)
    { encodeParameterSet(oauthParams,encodedParameters);
    }
    if (requestBody!=null)
    { encodeParameterSet(requestBody,encodedParameters);
    }
    Collections.sort(encodedParameters);
    boolean first=true;
    for (Pair param:encodedParameters)
    { 
      if (first)
      { first=false;
      }
      else
      { temp.append("&");
      }
      temp.append(param.name).append("=").append(param.value);
    }
    percentEncode(temp.toString(),buf);
  }
  
  public static final void encodeParameterSet
    (VariableMap params,List<Pair> encodedParameters)
    throws IOException
  {
    StringBuilder paramBuf=new StringBuilder();
    for (Map.Entry<String,List<String>> entry:params.entrySet())
    {
      percentEncode(entry.getKey(),paramBuf);
      String name=paramBuf.toString();
      paramBuf.setLength(0);
      
      for (String value:entry.getValue())
      {
        percentEncode(value,paramBuf);
        value=paramBuf.toString();
        paramBuf.setLength(0);
        encodedParameters.add(new Pair(name,value));
      }
    }
    
  }
  
  public static final String percentEncode(String input)
  {
    try
    { 
      StringBuffer buf=new StringBuffer();
      percentEncode(input,buf);
      return buf.toString();
    }
    catch (IOException x)
    { throw new RuntimeException(x);
    }
  }
  
  public static final void percentEncode(String input,Appendable buf)
    throws IOException
  {
    for (char chr:input.toCharArray())
    { 
      if (chr>=0x41 && chr<=0x5A       // lowercase
          || chr>=0x61 && chr<=0x7A    // uppercase
          || chr>=0x30 && chr<=0x39    // number
          || chr=='-'
          || chr=='.'
          || chr=='_'
          || chr=='~'
          )
      { buf.append(chr);
      }
      else
      {
        if (chr>255)
        {
          int hibyte= (chr & 0xFF00) >> 8;
          encodeIntToPercentString(hibyte,buf);
          int lobyte= (chr & 0x00FF);
          encodeIntToPercentString(lobyte,buf);
          
        }
        else
        {
          encodeIntToPercentString((int) chr,buf);
        }
      }
    }
    
  }
  
  public static final void encodeIntToPercentString(int val,Appendable buf)
    throws IOException
  { 
    buf.append("%");
    String hexString=Integer.toHexString(val).toUpperCase();
    if (hexString.length()==1)
    { buf.append("0");
    }
    buf.append(hexString);
  }
  
  static class Pair
    implements Comparable<Pair>
  {
    final String name;
    final String value;
    
    public Pair(String name,String value)
    { 
      this.name=name;
      this.value=value;
    }

    @Override
    public int compareTo(
      Pair o)
    {
      int ret=name.compareTo(o.name);
      if (ret==0)
      { ret=value.compareTo(o.value);
      }
      return ret;
    }
  }
  
}
