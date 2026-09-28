package burp;

import burp.BodyConverter.ConversionException;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Menu implements IContextMenuFactory {
    private final IBurpExtenderCallbacks m_callbacks;
    private final IExtensionHelpers m_helpers;

    private interface Converter {
        byte[] convert(IExtensionHelpers helpers, byte[] request) throws ConversionException;
    }

    public Menu(IBurpExtenderCallbacks callbacks) {
        m_callbacks = callbacks;
        m_helpers = callbacks.getHelpers();
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>();

        byte context = invocation.getInvocationContext();

        if (context != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                && context != IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
            return menus;
        }

        IHttpRequestResponse[] selected = invocation.getSelectedMessages();

        if (selected == null || selected.length == 0) {
            return menus;
        }

        final IHttpRequestResponse iReqResp = selected[0];

        menus.add(createItem("Convert to XML", iReqResp, Utilities::convertToXML));
        menus.add(createItem("Convert to JSON", iReqResp, Utilities::convertToJSON));
        menus.add(createItem("Convert to x-www-form-urlencoded", iReqResp, Utilities::convertToUrlEncoded));
        menus.add(createItem("Convert POST to GET", iReqResp, Utilities::convertPostToGet));
        return menus;
    }

    private JMenuItem createItem(final String label, final IHttpRequestResponse iReqResp, final Converter converter) {
        JMenuItem item = new JMenuItem(label);

        item.addActionListener(e -> {
            try {
                iReqResp.setRequest(converter.convert(m_helpers, iReqResp.getRequest()));
            } catch (ConversionException ex) {
                reportError(label, ex.getMessage());
            } catch (Exception ex) {
                reportError(label, ex.toString());
            }
        });

        return item;
    }

    private void reportError(String action, String message) {
        m_callbacks.printError(action + " failed: " + message);
        JOptionPane.showMessageDialog(null, message, "Content-Type Converter: " + action, JOptionPane.WARNING_MESSAGE);
    }
}
