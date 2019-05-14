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

import java.net.URI;

import spiralcraft.lang.Reflector;
import spiralcraft.lang.reflect.BeanReflector;
import spiralcraft.log.Level;


/**
 * OAuth 2 Client
 * 
 * @author mike
 *
 */
public class Client
{
  
  private URI credentialRequestURI;

  String clientId;
  String realm;
  String sharedSecret;
  String credentialRequestVerb="GET";
  URI authorizationURI;
  URI tokenRequestURI;
  String tokenRequestVerb="POST";
  URI redirectURI;
  URI tokenInvalidateURI;
  String signatureMethod;
  URI apiURI;
  Level logLevel=Level.INFO;
  
  protected Reflector<Session> sessionReflector
    =BeanReflector.<Session>getInstance(Session.class);
  
  /**
   * The preconfigured ID assigned by the server/service provider to this 
   *   client
   * 
   * @param clientId
   */
  public void setClientId(String clientId)
  { this.clientId=clientId;
  }
  
  public void setRealm(String realm)
  { this.realm=realm;
  }
  
  /**
   * The preconfigured secret shared with the server/service provider used
   *   to sign protocol data.
   *   
   * @param sharedSecret
   */
  public void setSharedSecret(String sharedSecret)
  { this.sharedSecret=sharedSecret;
  }
  
  public URI getCredentialRequestURI()
  { return credentialRequestURI;
  }
  
  /**
   * The URI of the initial OAuth2 request to the authentication provider / service
   */
  public void setCredentialRequestURI(URI credentialRequestURI)
  { this.credentialRequestURI=credentialRequestURI;
  }

  public void setCredentialRequestVerb(String credentialRequestVerb)
  { this.credentialRequestVerb=credentialRequestVerb;
  }

  public void setAuthorizationURI(URI authorizationURI)
  { this.authorizationURI=authorizationURI;
  }

  public void setTokenRequestURI(URI tokenRequestURI)
  { this.tokenRequestURI=tokenRequestURI;
  }
  
  public void setRedirectURI(URI redirectURI)
  { this.redirectURI=redirectURI;
  }
  
  public void setTokenInvalidateURI(URI tokenInvalidateURI)
  { this.tokenInvalidateURI=tokenInvalidateURI;
  }
  
  public void setApiURI(URI apiURI)
  { this.apiURI=apiURI;
  }

  public URI getApiURI()
  { return apiURI;
  }
  
  public Session newSession()
  { return new Session(this);
  }
  
  public void setLogLevel(Level logLevel)
  { this.logLevel=logLevel;
  }
  
}
