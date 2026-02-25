document.addEventListener('DOMContentLoaded', () => {
    // --- Boot Sequence Animation ---
    const bootLines = [
        "INITIALIZING SYSTEM MODULES...",
        "KERNEL BOOT... [OK]",
        "MOUNTING ENCRYPTED FILE SYSTEM... [OK]",
        "ESTABLISHING NOSTR RELAY CONNECTION... [OK]",
        "VERIFYING BIP-85 DERIVATION TREE... [OK]",
        "DECRYPTING VAULT... [OK]",
        "SYSTEM READY. LAUNCHING TUI..."
    ];

    const bootTextElement = document.getElementById('boot-text');
    const bootSequenceElement = document.getElementById('boot-sequence');
    const mainContentElement = document.getElementById('main-content');

    let currentLine = 0;

    function typeLine() {
        if (!bootTextElement) return;

        if (currentLine < bootLines.length) {
            bootTextElement.textContent += bootLines[currentLine] + "\n";
            currentLine++;
            
            // Random delay between lines to simulate processing (50ms to 250ms)
            const delay = Math.random() * 200 + 50;
            setTimeout(typeLine, delay);
        } else {
            // End boot sequence
            setTimeout(() => {
                bootSequenceElement.style.opacity = '0';
                bootSequenceElement.style.transition = 'opacity 0.5s ease-out';
                
                setTimeout(() => {
                    bootSequenceElement.style.display = 'none';
                    if(mainContentElement) {
                        mainContentElement.style.display = 'flex';
                    }
                }, 500);
            }, 600); // Wait 600ms after last line
        }
    }

    // Start boot sequence slightly after load
    setTimeout(typeLine, 300);

    // --- Copy to Clipboard Functionality ---
    const copyBtn = document.getElementById('copy-btn');
    const installCmd = document.getElementById('install-cmd');
    const copyFeedback = document.getElementById('copy-feedback');

    if (copyBtn && installCmd && copyFeedback) {
        copyBtn.addEventListener('click', () => {
            // Create a temporary textarea to hold the text to copy
            const tempTextArea = document.createElement('textarea');
            tempTextArea.value = installCmd.textContent;
            document.body.appendChild(tempTextArea);
            tempTextArea.select();
            
            try {
                // Execute the copy command
                document.execCommand('copy');
                copyFeedback.textContent = '>> Command copied to clipboard <<';
                copyFeedback.style.color = 'var(--accent-primary)';
                
                // Change icon temporarily to checkmark
                const icon = copyBtn.querySelector('i');
                if (icon) {
                    icon.className = 'fas fa-check';
                }
                copyBtn.style.color = 'var(--accent-primary)';
                
                // Reset after 2 seconds
                setTimeout(() => {
                    copyFeedback.textContent = '';
                    if (icon) {
                        icon.className = 'far fa-copy';
                    }
                    copyBtn.style.color = '';
                }, 2000);
            } catch (err) {
                copyFeedback.textContent = '[ERROR: Failed to copy]';
                copyFeedback.style.color = 'var(--accent-danger)';
            }
            
            // Remove the temporary textarea
            document.body.removeChild(tempTextArea);
        });
    }
});
