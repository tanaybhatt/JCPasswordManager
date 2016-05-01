import steganography.cardmanager.APDUSender;
import steganography.cardmanager.ResponseStatus;
import javax.swing.JOptionPane;

public class DHMain extends javax.swing.JFrame {

    public DHMain() {
        try {
            APDUSender.Initialize();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error while communicating with card.", "Exception", JOptionPane.PLAIN_MESSAGE);
            System.exit(-1);
        }
        promptLogin();
        initComponents();
        java.awt.Dimension dim = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        setSize(610, 455);
        setResizable(false);
    }

    private void initComponents() {
        jdp = new javax.swing.JDesktopPane();
        jMenuBar1 = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        toolsMenu = new javax.swing.JMenu();
        fileMenu1 = new javax.swing.JMenu();
        embedMenu = new javax.swing.JMenuItem();
        changePinMenu = new javax.swing.JMenuItem();
        regeneratePasswordMenu = new javax.swing.JMenuItem();
        extractmenu = new javax.swing.JMenuItem();
        exitmenu = new javax.swing.JMenuItem();
        aboutMenu = new javax.swing.JMenuItem();
        piclabel = new javax.swing.JLabel(new javax.swing.ImageIcon("new2.jpg"));
        piclabel.setBounds(0, 0, 600, 400);
        add(piclabel);
        setTitle("Audio-Stego");
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                exitForm(evt);
            }
        });
        getContentPane().add(jdp, java.awt.BorderLayout.CENTER);

        fileMenu.setMnemonic('F');
        fileMenu.setText("File");
        fileMenu1.setMnemonic('h');
        fileMenu1.setText("Help");
        toolsMenu.setMnemonic('t');
        toolsMenu.setText("Tools");
        changePinMenu.setMnemonic('p');
        changePinMenu.setText("Change PIN");
        changePinMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                changePinMenuActionPerformed(evt);
            }
        });
        regeneratePasswordMenu.setMnemonic('R');
        regeneratePasswordMenu.setText("Regenerate Key");
        regeneratePasswordMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                regeneratePasswordMenuActionPerformed(evt);
            }
        });
        toolsMenu.add(changePinMenu);
        toolsMenu.add(regeneratePasswordMenu);
        embedMenu.setMnemonic('m');
        embedMenu.setText("Embed");
        embedMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                embedMenuActionPerformed(evt);
            }
        });
        fileMenu.add(embedMenu);
        extractmenu.setMnemonic('e');
        extractmenu.setText("Extract");
        extractmenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                extractmenuActionPerformed(evt);
            }
        });

        fileMenu.add(extractmenu);
        exitmenu.setMnemonic('x');
        exitmenu.setText("Exit");
        exitmenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitmenuActionPerformed(evt);
            }
        });
        fileMenu1.add(aboutMenu);
        aboutMenu.setMnemonic('a');
        aboutMenu.setText("About");
        aboutMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aboutMenuActionPerformed(evt);
            }
        });
        fileMenu.add(exitmenu);
        fileMenu1.add(aboutMenu);
        jMenuBar1.add(fileMenu);
        jMenuBar1.add(fileMenu1);
        jMenuBar1.add(toolsMenu);

        setJMenuBar(jMenuBar1);
        pack();
    }

    private void exitmenuActionPerformed(java.awt.event.ActionEvent evt) {
        System.exit(0);
    }

    private void extractmenuActionPerformed(java.awt.event.ActionEvent evt) {
        piclabel.setVisible(false);
        WizardFrame wf = new ExtractAction(this).getWizardFrame();
        jdp.add(wf);
        wf.moveToFront();
    }

    private void embedMenuActionPerformed(java.awt.event.ActionEvent evt) {
        System.out.println("Embed Action Selected..");

        piclabel.setVisible(false);
        WizardFrame wf = new EmbedAction(this).getWizardFrame();
        jdp.add(wf);
        wf.moveToFront();
    }

    private void aboutMenuActionPerformed(java.awt.event.ActionEvent evt) {
        javax.swing.JOptionPane.showMessageDialog(this, "AUDIO HIDING USING STEGNOGRAPHY\n\n" + "Created by : Arunprasath Shankar", "About", javax.swing.JOptionPane.PLAIN_MESSAGE);
    }

    private void exitForm(java.awt.event.WindowEvent evt) {
        System.exit(0);
    }

    public static void main(String args[]) {
        new DHMain().show();
    }

    private void promptLogin() {
        boolean inputAccepted = false;
        while (!inputAccepted) {
            String pin = (String) JOptionPane.showInputDialog(this, "Enter PIN:", "Login", JOptionPane.QUESTION_MESSAGE);

            if (pin == null) {
                System.exit(0);
            }

            if (pin.isEmpty()) {
                JOptionPane.showMessageDialog(this, "PIN cannot be empty.");
                continue;
            }

            try {
                Integer.parseUnsignedInt(pin);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "PIN has to be numeric.");
                continue;
            }

            try {
                ResponseStatus result = APDUSender.SendPIN(pin);
                switch (result) {
                    case SW_OK:
                        inputAccepted = true;
                        APDUSender.initializeSecretChannelKey(pin);
                        break;
                    case SW_BAD_PIN:
                        JOptionPane.showMessageDialog(this, "Incorrect PIN. Try again.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    case SW_SECURITY_STATUS_NOT_SATISFIED:
                        JOptionPane.showMessageDialog(this, "Applet was blocked. Contact your manufacturer.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    default:
                        throw new Exception(result.toString());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error while communicating with card or keystore. " + ex, "Exception", JOptionPane.PLAIN_MESSAGE);
                System.exit(-1);
            }
        }
    }

    private void changePinMenuActionPerformed(java.awt.event.ActionEvent evt) {
        boolean inputAccepted = false;
        while (!inputAccepted) {
            String pin = (String) JOptionPane.showInputDialog(this, "Enter new PIN:", "Information", JOptionPane.QUESTION_MESSAGE);

            if (pin == null) {
                return;
            }

            if (pin.isEmpty()) {
                JOptionPane.showMessageDialog(this, "PIN cannot be empty.");
                continue;
            }

            try {
                Integer.parseUnsignedInt(pin);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "PIN has to be numeric.");
                continue;
            }

            try {
                ResponseStatus result = APDUSender.ChangePIN(pin);
                switch (result) {
                    case SW_OK:
                        inputAccepted = true;
                        APDUSender.changeKeyStorePassword(pin);
                        JOptionPane.showMessageDialog(this, "PIN successfully changed.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    case SW_SECURITY_STATUS_NOT_SATISFIED:
                        JOptionPane.showMessageDialog(this, "You are not authorized to change PIN.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    default:
                        throw new Exception();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error while communicating with card or keystore." + ex, "Exception", JOptionPane.PLAIN_MESSAGE);
            }
        }
    }

    private void regeneratePasswordMenuActionPerformed(java.awt.event.ActionEvent evt) {
        int n = JOptionPane.showConfirmDialog(this, "Are you sure? You won't be able to extract files hidden in the past.", "Warning!", JOptionPane.YES_NO_OPTION);
        if (n == JOptionPane.YES_OPTION) {
            try {
                ResponseStatus result = APDUSender.RegeneratePassword();
                switch (result) {
                    case SW_OK:
                        JOptionPane.showMessageDialog(this, "New key was successfully generated.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    case SW_SECURITY_STATUS_NOT_SATISFIED:
                        JOptionPane.showMessageDialog(this, "You are not authorized to regenerate the key.", "Information", JOptionPane.PLAIN_MESSAGE);
                        break;
                    default:
                        throw new Exception();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error while communicating with card.", "Exception", JOptionPane.PLAIN_MESSAGE);
            }
        }
    }

    private javax.swing.JMenuItem exitmenu;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JMenu fileMenu1;
    private javax.swing.JDesktopPane jdp;
    private javax.swing.JMenuItem extractmenu;
    private javax.swing.JMenuItem embedMenu;
    private javax.swing.JMenuItem aboutMenu;
    private javax.swing.JMenuBar jMenuBar1;
    public javax.swing.JLabel piclabel;
    private javax.swing.JMenu toolsMenu;
    private javax.swing.JMenuItem changePinMenu;
    private javax.swing.JMenuItem regeneratePasswordMenu;
}
