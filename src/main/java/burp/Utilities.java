package burp;

import burp.BodyConverter.ConversionException;
import burp.BodyConverter.Pair;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

public class Utilities {

    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String CONTENT_TYPE_XML = "application/xml;charset=UTF-8";
    private static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded;charset=UTF-8";

    private enum Format { JSON, XML, FORM, EMPTY }

    private static final class ParsedBody {
        final Format format;
        final JsonElement model;
        final List<Pair> pairs;

        ParsedBody(Format format, JsonElement model, List<Pair> pairs) {
            this.format = format;
            this.model = model;
            this.pairs = pairs;
        }

        static ParsedBody form(List<Pair> pairs) {
            return new ParsedBody(Format.FORM, BodyConverter.pairsToJson(pairs), pairs);
        }
    }

    public static byte[] convertToXML(IExtensionHelpers helpers, byte[] request) throws ConversionException {
        request = toPostIfGet(helpers, request);
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        String body = getBody(request, requestInfo);
        ParsedBody parsed = parseBody(requestInfo, body);

        String xml = parsed.format == Format.XML ? body : BodyConverter.toXml(parsed.model);

        return buildRequest(helpers, requestInfo, CONTENT_TYPE_XML, xml);
    }

    public static byte[] convertToJSON(IExtensionHelpers helpers, byte[] request) throws ConversionException {
        request = toPostIfGet(helpers, request);
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        String body = getBody(request, requestInfo);
        ParsedBody parsed = parseBody(requestInfo, body);

        String json;

        if (parsed.format == Format.JSON) {
            json = body;
        } else {
            json = BodyConverter.toJson(parsed.model, parsed.format == Format.XML);
        }

        return buildRequest(helpers, requestInfo, CONTENT_TYPE_JSON, json);
    }

    public static byte[] convertToUrlEncoded(IExtensionHelpers helpers, byte[] request) {
        request = toPostIfGet(helpers, request);
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        String body = getBody(request, requestInfo);

        List<Pair> pairs;

        try {
            ParsedBody parsed = parseBody(requestInfo, body);
            pairs = parsed.format == Format.FORM ? parsed.pairs : BodyConverter.jsonToPairs(parsed.model);
        } catch (ConversionException e) {
            pairs = new ArrayList<>();
            pairs.add(new Pair("value", body));
        }

        return buildRequest(helpers, requestInfo, CONTENT_TYPE_FORM, BodyConverter.encodePairs(pairs));
    }

    public static byte[] convertPostToGet(IExtensionHelpers helpers, byte[] request) throws ConversionException {
        String method = helpers.analyzeRequest(request).getMethod();

        if ("GET".equals(method)) {
            throw new ConversionException("Request is already a GET request");
        }

        byte[] formRequest = convertToUrlEncoded(helpers, request);

        if (!"POST".equals(method)) {
            formRequest = replaceMethod(helpers, formRequest, "POST");
        }

        return helpers.toggleRequestMethod(formRequest);
    }

    private static ParsedBody parseBody(IRequestInfo requestInfo, String body) throws ConversionException {
        if (body.trim().isEmpty()) {
            return new ParsedBody(Format.EMPTY, new JsonObject(), new ArrayList<Pair>());
        }

        ParsedBody declared = parseDeclaredType(requestInfo, body);

        if (declared != null) {
            return declared;
        }

        // Missing or wrong Content-Type: sniff the body instead.
        JsonElement json = BodyConverter.tryParseJson(body);

        if (json != null) {
            return new ParsedBody(Format.JSON, json, null);
        }

        JsonElement xml = BodyConverter.tryParseXml(body);

        if (xml != null) {
            return new ParsedBody(Format.XML, xml, null);
        }

        if (BodyConverter.looksUrlEncoded(body)) {
            return ParsedBody.form(BodyConverter.parseFormPairs(body));
        }

        throw new ConversionException("Unable to recognise the request body as JSON, XML or form data");
    }

    private static ParsedBody parseDeclaredType(IRequestInfo requestInfo, String body) {
        switch (requestInfo.getContentType()) {
            case IRequestInfo.CONTENT_TYPE_JSON: {
                JsonElement json = BodyConverter.tryParseJson(body);
                return json == null ? null : new ParsedBody(Format.JSON, json, null);
            }
            case IRequestInfo.CONTENT_TYPE_XML: {
                JsonElement xml = BodyConverter.tryParseXml(body);
                return xml == null ? null : new ParsedBody(Format.XML, xml, null);
            }
            case IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                return ParsedBody.form(BodyConverter.parseFormPairs(body));
            case IRequestInfo.CONTENT_TYPE_MULTIPART:
            case IRequestInfo.CONTENT_TYPE_AMF: {
                List<Pair> pairs = getBodyParameterPairs(requestInfo);
                return pairs.isEmpty() ? null : ParsedBody.form(pairs);
            }
            default:
                return null;
        }
    }

    /** Body parameters parsed by Burp; URL parameters stay in the request line and cookies are skipped. */
    private static List<Pair> getBodyParameterPairs(IRequestInfo requestInfo) {
        List<Pair> pairs = new ArrayList<>();

        for (IParameter parameter : requestInfo.getParameters()) {
            if (parameter.getType() == IParameter.PARAM_BODY) {
                pairs.add(new Pair(parameter.getName(), parameter.getValue()));
            }
        }

        return pairs;
    }

    private static byte[] toPostIfGet(IExtensionHelpers helpers, byte[] request) {
        if ("GET".equals(helpers.analyzeRequest(request).getMethod())) {
            return helpers.toggleRequestMethod(request);
        }

        return request;
    }

    private static byte[] replaceMethod(IExtensionHelpers helpers, byte[] request, String method) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String requestLine = headers.get(0);
        int space = requestLine.indexOf(' ');
        headers.set(0, method + (space >= 0 ? requestLine.substring(space) : ""));

        int bodyOffset = requestInfo.getBodyOffset();
        byte[] body = new byte[request.length - bodyOffset];
        System.arraycopy(request, bodyOffset, body, 0, body.length);

        return helpers.buildHttpMessage(headers, body);
    }

    private static String getBody(byte[] request, IRequestInfo requestInfo) {
        int bodyOffset = requestInfo.getBodyOffset();
        return new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.UTF_8);
    }

    private static byte[] buildRequest(IExtensionHelpers helpers, IRequestInfo requestInfo, String contentType, String body) {
        List<String> headers = requestInfo.getHeaders();
        Iterator<String> iter = headers.iterator();
        iter.next(); // request line

        while (iter.hasNext()) {
            if (iter.next().toLowerCase(Locale.ROOT).startsWith("content-type:")) {
                iter.remove();
            }
        }

        headers.add("Content-Type: " + contentType);

        return helpers.buildHttpMessage(headers, body.getBytes(StandardCharsets.UTF_8));
    }
}
