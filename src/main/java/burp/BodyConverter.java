package burp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import org.w3c.dom.Document;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure body conversions between JSON, XML and x-www-form-urlencoded.
 * Uses Gson's JsonObject (insertion ordered) as the intermediate model so key order is preserved.
 */
public final class BodyConverter {

    public static final String XML_ROOT = "root";

    private static final Gson COMPACT = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final Gson PRETTY = new GsonBuilder().disableHtmlEscaping().serializeNulls().setPrettyPrinting().create();
    private static final Pattern BRACKET_KEY = Pattern.compile("^([^\\[\\]]*)((?:\\[[^\\[\\]]*\\])+)$");
    private static final Pattern BRACKET_SEGMENT = Pattern.compile("\\[([^\\[\\]]*)\\]");

    private BodyConverter() {
    }

    public static final class ConversionException extends Exception {
        public ConversionException(String message) {
            super(message);
        }

        public ConversionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static final class Pair {
        public final String key;
        public final String value;

        public Pair(String key, String value) {
            this.key = key == null ? "" : key;
            this.value = value == null ? "" : value;
        }
    }

    // ---------------------------------------------------------------- JSON

    /** Strict JSON parse; returns null when the body is not a single valid JSON document. */
    public static JsonElement tryParseJson(String body) {
        if (body == null || body.trim().isEmpty()) {
            return null;
        }

        try {
            JsonReader reader = new JsonReader(new StringReader(body));
            reader.setLenient(false);
            JsonElement element = COMPACT.getAdapter(JsonElement.class).read(reader);

            if (reader.peek() != JsonToken.END_DOCUMENT) {
                return null;
            }

            return element;
        } catch (Exception e) {
            return null;
        }
    }

    public static String toJson(JsonElement element, boolean pretty) {
        return (pretty ? PRETTY : COMPACT).toJson(element);
    }

    // ---------------------------------------------------------------- XML

    /** Parses XML into a JSON model. All text values are kept as strings. Returns null when not XML. */
    public static JsonElement tryParseXml(String body) {
        if (body == null || !body.trim().startsWith("<")) {
            return null;
        }

        try {
            DocumentBuilder builder = secureDocumentBuilderFactory().newDocumentBuilder();
            builder.setErrorHandler(null);
            Document doc = builder.parse(new InputSource(new StringReader(body.trim())));
            Element root = doc.getDocumentElement();
            JsonElement content = elementToJson(root);

            if (XML_ROOT.equals(root.getNodeName())) {
                if (content.isJsonObject()) {
                    return content;
                }

                if (content.isJsonPrimitive() && content.getAsString().isEmpty()) {
                    return new JsonObject();
                }
            }

            JsonObject wrapper = new JsonObject();
            wrapper.add(root.getNodeName(), content);
            return wrapper;
        } catch (Exception e) {
            return null;
        }
    }

    private static JsonElement elementToJson(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        List<Element> children = new ArrayList<>();
        StringBuilder text = new StringBuilder();
        NodeList nodes = element.getChildNodes();

        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                children.add((Element) node);
            } else if (node.getNodeType() == Node.TEXT_NODE || node.getNodeType() == Node.CDATA_SECTION_NODE) {
                text.append(node.getNodeValue());
            }
        }

        String trimmedText = text.toString().trim();

        if (attributes.getLength() == 0 && children.isEmpty()) {
            return new JsonPrimitive(trimmedText);
        }

        JsonObject object = new JsonObject();

        for (int i = 0; i < attributes.getLength(); i++) {
            Node attribute = attributes.item(i);
            object.addProperty(attribute.getNodeName(), attribute.getNodeValue());
        }

        for (Element child : children) {
            addOrAppend(object, child.getNodeName(), elementToJson(child));
        }

        if (!trimmedText.isEmpty()) {
            addOrAppend(object, "content", new JsonPrimitive(trimmedText));
        }

        return object;
    }

    /** Serializes a JSON model as pretty printed XML wrapped in a {@code <root>} element. */
    public static String toXml(JsonElement element) throws ConversionException {
        try {
            Document doc = secureDocumentBuilderFactory().newDocumentBuilder().newDocument();
            Element root = doc.createElement(XML_ROOT);
            doc.appendChild(root);

            if (element.isJsonArray()) {
                appendArray(doc, root, "array", element.getAsJsonArray());
            } else {
                appendValue(doc, root, element);
            }

            return prettyPrint(doc);
        } catch (ConversionException e) {
            throw e;
        } catch (Exception e) {
            throw new ConversionException("Unable to build XML: " + e.getMessage(), e);
        }
    }

    private static void appendValue(Document doc, Element parent, JsonElement value) throws ConversionException {
        if (value.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : value.getAsJsonObject().entrySet()) {
                if (entry.getValue().isJsonArray()) {
                    appendArray(doc, parent, entry.getKey(), entry.getValue().getAsJsonArray());
                } else {
                    Element child = createElement(doc, entry.getKey());
                    parent.appendChild(child);
                    appendValue(doc, child, entry.getValue());
                }
            }
        } else if (value.isJsonArray()) {
            appendArray(doc, parent, "array", value.getAsJsonArray());
        } else {
            parent.setTextContent(value.isJsonNull() ? "null" : value.getAsString());
        }
    }

    private static void appendArray(Document doc, Element parent, String name, JsonArray array) throws ConversionException {
        for (JsonElement item : array) {
            Element child = createElement(doc, name);
            parent.appendChild(child);
            appendValue(doc, child, item);
        }
    }

    private static Element createElement(Document doc, String name) throws ConversionException {
        try {
            return doc.createElement(name);
        } catch (DOMException e) {
            throw new ConversionException("Key \"" + name + "\" is not a valid XML element name");
        }
    }

    private static DocumentBuilderFactory secureDocumentBuilderFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    private static String prettyPrint(Document xml) throws Exception {
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        tf.setOutputProperty(OutputKeys.INDENT, "yes");
        tf.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        StringWriter out = new StringWriter();
        tf.transform(new DOMSource(xml), new StreamResult(out));
        return out.toString();
    }

    // ---------------------------------------------------------------- x-www-form-urlencoded

    public static boolean looksUrlEncoded(String body) {
        return body.contains("=") || body.contains("&");
    }

    /** Splits a form body into decoded pairs, keeping order, duplicates and whitespace. */
    public static List<Pair> parseFormPairs(String body) {
        List<Pair> pairs = new ArrayList<>();

        if (body == null || body.isEmpty()) {
            return pairs;
        }

        for (String pair : body.split("&", -1)) {
            if (pair.isEmpty()) {
                continue;
            }

            int idx = pair.indexOf('=');
            String key = idx >= 0 ? pair.substring(0, idx) : pair;
            String value = idx >= 0 ? pair.substring(idx + 1) : "";
            pairs.add(new Pair(urlDecode(key), urlDecode(value)));
        }

        return pairs;
    }

    /** Builds a JSON object from form pairs; bracket keys (user[name], tags[0], tags[]) become nested values. */
    public static JsonObject pairsToJson(List<Pair> pairs) {
        JsonObject root = new JsonObject();

        for (Pair pair : pairs) {
            List<String> path = splitBracketKey(pair.key);

            if (path == null || !insertPath(root, path, pair.value)) {
                addOrAppend(root, pair.key, new JsonPrimitive(pair.value));
            }
        }

        return (JsonObject) arraysFromIndexedObjects(root);
    }

    private static List<String> splitBracketKey(String key) {
        Matcher matcher = BRACKET_KEY.matcher(key);

        if (!matcher.matches() || matcher.group(1).isEmpty()) {
            return null;
        }

        List<String> path = new ArrayList<>();
        path.add(matcher.group(1));
        Matcher segment = BRACKET_SEGMENT.matcher(matcher.group(2));

        while (segment.find()) {
            path.add(segment.group(1));
        }

        return path;
    }

    private static boolean insertPath(JsonObject root, List<String> path, String value) {
        JsonObject current = root;

        for (int i = 0; i < path.size() - 1; i++) {
            String name = segmentName(current, path.get(i));
            JsonElement next = current.get(name);

            if (next == null) {
                next = new JsonObject();
                current.add(name, next);
            } else if (!next.isJsonObject()) {
                return false;
            }

            current = next.getAsJsonObject();
        }

        String leaf = segmentName(current, path.get(path.size() - 1));

        if (current.has(leaf) && current.get(leaf).isJsonObject()) {
            return false;
        }

        addOrAppend(current, leaf, new JsonPrimitive(value));
        return true;
    }

    /** An empty segment (tags[]) appends to the container. */
    private static String segmentName(JsonObject container, String segment) {
        return segment.isEmpty() ? String.valueOf(container.size()) : segment;
    }

    /** Objects whose keys are exactly "0".."n-1" in order become arrays. */
    private static JsonElement arraysFromIndexedObjects(JsonElement element) {
        if (!element.isJsonObject()) {
            return element;
        }

        JsonObject object = element.getAsJsonObject();

        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            entry.setValue(arraysFromIndexedObjects(entry.getValue()));
        }

        if (object.size() == 0) {
            return object;
        }

        int index = 0;

        for (String key : object.keySet()) {
            if (!key.equals(String.valueOf(index++))) {
                return object;
            }
        }

        JsonArray array = new JsonArray();

        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            array.add(entry.getValue());
        }

        return array;
    }

    /** Flattens a JSON model into form pairs using bracket notation for nested values. */
    public static List<Pair> jsonToPairs(JsonElement element) {
        List<Pair> pairs = new ArrayList<>();

        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                flatten(pairs, entry.getKey(), entry.getValue());
            }
        } else {
            flatten(pairs, "value", element);
        }

        return pairs;
    }

    private static void flatten(List<Pair> pairs, String key, JsonElement value) {
        if (value.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : value.getAsJsonObject().entrySet()) {
                flatten(pairs, key + "[" + entry.getKey() + "]", entry.getValue());
            }
        } else if (value.isJsonArray()) {
            JsonArray values = value.getAsJsonArray();

            for (int i = 0; i < values.size(); i++) {
                flatten(pairs, key + "[" + i + "]", values.get(i));
            }
        } else {
            pairs.add(new Pair(key, value.isJsonNull() ? "" : value.getAsString()));
        }
    }

    public static String encodePairs(List<Pair> pairs) {
        StringBuilder body = new StringBuilder();

        for (Pair pair : pairs) {
            if (body.length() > 0) {
                body.append('&');
            }

            body.append(urlEncode(pair.key)).append('=').append(urlEncode(pair.value));
        }

        return body.toString();
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Lenient decode: malformed escapes (e.g. a raw %) keep the original text instead of failing. */
    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    // ---------------------------------------------------------------- helpers

    /** Adds a value; a repeated key turns the existing value into an array. */
    private static void addOrAppend(JsonObject object, String key, JsonElement value) {
        JsonElement existing = object.get(key);

        if (existing == null) {
            object.add(key, value == null ? JsonNull.INSTANCE : value);
        } else if (existing.isJsonArray()) {
            existing.getAsJsonArray().add(value);
        } else {
            JsonArray array = new JsonArray();
            array.add(existing);
            array.add(value);
            object.add(key, array);
        }
    }
}
