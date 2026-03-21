/// WebView Shield — Hardened defaults for in-app WebView usage.
class WebViewShield {
  WebViewShield._();
  /// The singleton [WebViewShield] instance.
  static final WebViewShield instance = WebViewShield._();

  final Set<String> _allowedHosts = {};
  bool _blockJavascriptUrls = true;
  bool _blockFileUrls = true;
  bool _enforceHttps = true;

  /// Configure the WebView shield.
  void configure({
    Set<String>? allowedHosts,
    bool? blockJavascriptUrls,
    bool? blockFileUrls,
    bool? enforceHttps,
  }) {
    if (allowedHosts != null) _allowedHosts.addAll(allowedHosts);
    if (blockJavascriptUrls != null) _blockJavascriptUrls = blockJavascriptUrls;
    if (blockFileUrls != null) _blockFileUrls = blockFileUrls;
    if (enforceHttps != null) _enforceHttps = enforceHttps;
  }

  /// Validate a URL before loading it in a WebView.
  String? validateUrl(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return 'Invalid URL format';
    if (_blockJavascriptUrls && uri.scheme == 'javascript') return 'JavaScript URLs blocked';
    if (_blockFileUrls && uri.scheme == 'file') return 'File URLs blocked';
    if (_enforceHttps && uri.scheme == 'http' && uri.host != 'localhost' && uri.host != '127.0.0.1') {
      return 'HTTP not allowed — use HTTPS';
    }
    if (_allowedHosts.isNotEmpty && !_allowedHosts.contains(uri.host)) {
      return 'Host ${uri.host} not in allowed list';
    }
    return null;
  }

  /// Get recommended WebView settings.
  Map<String, dynamic> get recommendedSettings => {
    'javaScriptEnabled': true,
    'domStorageEnabled': true,
    'allowFileAccess': false,
    'allowUniversalAccessFromFileURLs': false,
    'allowFileAccessFromFileURLs': false,
    'javaScriptCanOpenWindowsAutomatically': false,
    'mediaPlaybackRequiresUserGesture': true,
  };

  /// Resets all WebView shield settings to their secure defaults.
  void reset() {
    _allowedHosts.clear();
    _blockJavascriptUrls = true;
    _blockFileUrls = true;
    _enforceHttps = true;
  }
}
