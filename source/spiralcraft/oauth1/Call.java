//
//Copyright (c) 2009 Michael Toth
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
import java.io.InputStreamReader;
import java.net.URI;
import java.util.HashMap;

import spiralcraft.common.ContextualException;
import spiralcraft.text.ParseException;
import spiralcraft.util.string.StringConverter;
import spiralcraft.vfs.Resource;
import spiralcraft.vfs.task.Query;
import spiralcraft.vfs.url.URLMessage;

import spiralcraft.json.DataReader;
import spiralcraft.json.Parser;
import spiralcraft.lang.BindException;
import spiralcraft.lang.Channel;
import spiralcraft.lang.Focus;
import spiralcraft.lang.Reflector;
import spiralcraft.lang.reflect.BeanReflector;
import spiralcraft.lang.util.DictionaryBinding;
import spiralcraft.lang.util.LangUtil;
import spiralcraft.log.ClassLog;

public class Call<Tresult>
  extends Query<Tresult>
{

  private static final ClassLog log
    =ClassLog.getInstance(Call.class);
  @SuppressWarnings("rawtypes")
  private static HashMap<Class,StringConverter> converterMap
    =new HashMap<Class,StringConverter>();

  
  private Reflector<Client> clientReflector
    =BeanReflector.getInstance(Client.class);
  private Channel<Session> sessionChannel;
  private Client client;

  
  @Override
  protected URI getDefaultURI()
  { return client.apiURI;
  }
  
  @Override
  protected Focus<?> bindImports(Focus<?> focus)
    throws BindException
  { 
    client=LangUtil.<Client>assertInstance(clientReflector.getTypeURI(),focus);

    sessionChannel
      =LangUtil.assertChannel(client.sessionReflector.getTypeURI(),focus);
    
    return super.bindImports(focus);
  }
  
  @Override
  public Focus<?> bindExports(Focus<?> exportChain)
    throws ContextualException
  {
    if (uriQueryBindings!=null)
    {
      for (DictionaryBinding<?> binding:uriQueryBindings)
      { binding.setConverterMap(converterMap);
      }
    }
    exportChain=super.bindExports(exportChain);
    return exportChain;
  }
  
  
  @Override
  protected Operation resolveOperation(OperationType type)
  {
    switch (type)
    {
      case GET:
        return new OAuthReadOperation();
    }
    return super.resolveOperation(type);

  }  
  
  class OAuthReadOperation
    extends GetOperation
  {
    
    @Override
    protected InputStream accessResource(Resource resource)
      throws IOException
    { 
      URI uri=resource.getURI();
      URLMessage message=sessionChannel.get().call("GET",uri,null);
      return message.getInputStream();
    }
    
    @SuppressWarnings("unchecked")
    @Override
    protected Tresult readStream(InputStream in,URI uri)
      throws IOException
    {
      DataReader reader=new DataReader(getResultReflector(),null);
      reader.setIgnoreUnrecognizedFields(true);
      try
      {
        Parser parser=new Parser(new InputStreamReader(in),reader);
        parser.parse();
        return (Tresult) reader.getValue();
      }
      catch (ParseException x)
      { throw new IOException("Error reading "+uri,x);
      }
    }
    
  }
  
}
