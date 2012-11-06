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
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import spiralcraft.lang.BindException;
import spiralcraft.lang.Channel;
import spiralcraft.lang.Focus;
import spiralcraft.lang.spi.SimpleChannel;
import spiralcraft.lang.spi.ThreadLocalChannel;
import spiralcraft.lang.util.LangUtil;
import spiralcraft.log.Level;
import spiralcraft.net.http.VariableMap;

import spiralcraft.servlet.autofilter.spi.FocusFilter;

/**
 * Exposes oauth functionality and state for use by web applications
 * 
 * @author mike
 *
 */
public class Filter
  extends FocusFilter<Session>
{

  private Client client;
  protected ThreadLocalChannel<Session> channel;
  protected Channel<HttpServletRequest> requestChannel;
  private URI authSuccessLocation=URI.create("success");
  private URI authFailureLocation=URI.create("failure");
  private boolean invalidateOnLogout=false;
        
  { setUsesRequest(true);
  }
  
  /**
   * The location to redirect to after completion of a successful
   *   authentication process, if no return URI was provided when the
   *   oauth session was started.
   * 
   * @param authSuccessLocation
   */
  public void setAuthSuccessLocation(URI authSuccessLocation)
  { this.authSuccessLocation=authSuccessLocation;
  }
  
  public void setInvalidateOnLogout(boolean invalidateOnLogout)
  { this.invalidateOnLogout=invalidateOnLogout;
  }
  
  /**
   * The Client object which talks to the oauth server
   * 
   * @param apiKey
   */
  public void setClient(Client client)
  { this.client=client;
  }
    
  public Client getClient()
  { return this.client;
  }

  
  @Override
  public Focus<?> bindExports(Focus<?> focus)
    throws BindException
  { 
    focus=focus.chain(new SimpleChannel<Client>(client,true));
    requestChannel=LangUtil.assertChannel(HttpServletRequest.class,focus);
    return focus;
  }
  

  
  /**
   * Start the authentication sequence and return to the specified URI 
   *   when complete 
   * 
   * @param redirectURIString
   * @return
   */
  public URI startAuthSequence(String callbackURIString)
  {
    if (debug)
    { log.fine("Callback URI is "+callbackURIString);
    }
    URI callbackURI=URI.create(callbackURIString);
    String state=null;
    String referer=null;
    if (callbackURI.getRawQuery()!=null)
    { 
      state=callbackURI.getRawQuery();
      VariableMap params=VariableMap.fromUrlEncodedString(state);
      referer=params.getFirst("referer");
      if (debug)
      { log.fine("Referer parameter = "+referer);
      }
    }

    Session session
      =this.<Session>getPrivateSessionState
        (requestChannel.get(),true);
    
    
    if (referer!=null)
    { session.setReturnURI(URI.create(referer));
    }
    
    try
    { return session.startAuthSequence(callbackURI);
    }
    catch (GeneralSecurityException x)
    {
      log.log(Level.WARNING,"Error starting oauth sequence",x);
      return session.getReturnURI();
    }
    catch (IOException x)
    {
      log.log(Level.WARNING,"Error starting oauth sequence",x);
      return session.getReturnURI();
    }
  }
  
  @Override
  protected Session newPrivateSessionState(HttpServletRequest request)
  { return client.newSession();
  }
    
  public URI readCallback(VariableMap query)
  { 
    HttpServletRequest request
      =requestChannel.get();
    
    if (debug)
    { log.fine("Got auth response "+request.getRequestURI()+"?"+request.getQueryString());
    }
    
    
    String authToken=query.getValue("oauth_token");
    String authVerifier=query.getValue("oauth_verifier");
    
    if (debug)
    { log.fine("Auth: "+authToken+":"+authVerifier);
    }
    
    Session session
      =this.<Session>getPrivateSessionState
        (requestChannel.get(),true);
    
    try
    { session.completeAuthSequence(authToken,authVerifier);
    }
    catch (IOException x)
    { log.log(Level.WARNING,"OAuth failure",x);
    }
    catch (GeneralSecurityException x)
    { log.log(Level.WARNING,"OAuth failure",x);
    }
    
    
    URI redirectURI=session.getReturnURI();
    if (redirectURI==null && authSuccessLocation!=null)
    { redirectURI=authSuccessLocation;
    }
    if (redirectURI==null)
    { return URI.create("/");
    }
    return redirectURI;
  }
  
  public URI abortAuthSequence(VariableMap query)
  {
    HttpServletRequest request
      =requestChannel.get();
    
    if (debug)
    { log.fine("Got abort response "+request.getRequestURI()+"?"+request.getQueryString());
    }
    
    String problem=query.getValue("oauth_problem");

    Session session
      =this.<Session>getPrivateSessionState
        (requestChannel.get(),true);
    
    session.abortAuthSequence(problem);
        
    URI redirectURI=session.getReturnURI();
    if (redirectURI==null && authFailureLocation!=null)
    { redirectURI=authFailureLocation;
    }
    if (redirectURI==null)
    { return URI.create("/");
    }
    return redirectURI;
  }

  public void logout()
  {
    Session session
      =this.<Session>getPrivateSessionState
        (requestChannel.get(),true);
    if (session==null || !session.isTokenValid())
    { return;
    }

    try
    { 
      if (invalidateOnLogout)
      { session.invalidate();
      }
      else
      { session.clear();
      }
    }
    catch (IOException x)
    { log.log(Level.WARNING,"Error on logout",x);
    }
  }
  
  public void clearSession()
  { channel.get().clear();
  }
  
  /**
   * Called -once- to create the Focus
   */
  @Override
  protected Focus<Session> createFocus
    (Focus<?> parentFocus)
    throws BindException
  { 
    if (client==null)
    { throw new BindException("No oauth client configured");
    }

    channel
      =new ThreadLocalChannel<Session>
        (client.sessionReflector);
    return parentFocus.chain(channel);
  }
  
  
  @Override
  protected void pushSubject
    (HttpServletRequest request,HttpServletResponse response) 
    throws BindException,ServletException
  {
    Session session
      =this.<Session>getPrivateSessionState(request,false);

    
    channel.push(session);
    if (debug)
    { 
      log.debug
        ("Credentials: "
        +session+"("+client.sessionReflector.getTypeURI()+")"
        );
    }
    // TODO: Make sure session is active here
    if (session!=null)
    {
      checkSessionValidity(session);
      
    }
    
  }

  
  private void checkSessionValidity(Session session)
  { 
    // Check expire time for access token and trigger a re-auth sequence
    //   somehow
  }
  

  
  @Override
  protected void popSubject(HttpServletRequest request)
  { channel.pop();
  }  
  

}
