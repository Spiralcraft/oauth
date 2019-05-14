package spiralcraft.oauth2;

import java.io.StringReader;

import spiralcraft.json.DataReader;
import spiralcraft.json.Parser;
import spiralcraft.lang.Reflector;
import spiralcraft.lang.reflect.BeanReflector;
import spiralcraft.text.ParseException;

public class AccessTokenResponse
{
  static Reflector<AccessTokenResponse> reflector
    =BeanReflector.<AccessTokenResponse>getInstance(AccessTokenResponse.class);
      
  static AccessTokenResponse fromJSON(String json)
    throws ParseException
  {
    DataReader dataReader=new DataReader(reflector,new AccessTokenResponse());
    Parser parser=new Parser(new StringReader(json),dataReader);
    parser.parse();
    return (AccessTokenResponse) dataReader.getValue();
  }
  
  public String accessToken;
  public long expiresIn;
  public String error;
  public String errorDescription;
  
  public String toString()
  { return super.toString()+": accessToken="+accessToken+" expiresIn="+expiresIn+" error="+error+" errorDescription="+errorDescription;
  }
}