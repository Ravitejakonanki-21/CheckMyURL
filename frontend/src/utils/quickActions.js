// QUICK ACTION FUNCTIONS WITH INLINE FEEDBACK
export const copyToClipboard = async (text, buttonElement) => {
  try {
    await navigator.clipboard.writeText(text);
    showInlineFeedback(buttonElement, 'Copied!');
  } catch (err) {
    // Fallback for older browsers
    const textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    showInlineFeedback(buttonElement, 'Copied!');
  }
};

export const showInlineFeedback = (buttonElement, message) => {
  const originalText = buttonElement.textContent;
  buttonElement.textContent = message;
  buttonElement.style.color = '#22c55e'; // Green color
  
  setTimeout(() => {
    buttonElement.textContent = originalText;
    buttonElement.style.color = ''; // Reset color
  }, 1500);
};

export const openLearnMore = (topic, buttonElement) => {
  const urls = { 
    ssl: "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security", 
    domain: "https://www.icann.org/resources/pages/whois-2018-01-17-en", 
    ports: "https://owasp.org/www-community/vulnerabilities/Port_Scanning", 
    headers: "https://owasp.org/www-project-secure-headers/", 
    keywords: "https://www.phishing.org/what-is-phishing", 
    ml: "https://en.wikipedia.org/wiki/Machine_learning_in_computer_security" 
  };
  urls[topic] && (window.open(urls[topic], '_blank'), showInlineFeedback(buttonElement, 'Opened!'));
};

export const reportFalsePositive = (field, value, buttonElement) => {
  const subject = `False Positive Report: ${field}`;
  const body = `I believe there's a false positive in the URL Scanner results:\n\nField: ${field}\nValue: ${value}\nURL: ${window.location.href}\n\nPlease review this result.`;
  const mailtoUrl = `mailto:support@urlscanner.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.location.href = mailtoUrl;
  showInlineFeedback(buttonElement, 'Reported!');
};