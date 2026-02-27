// PhishGuard Local AI Inference Engine - On-Device ML
(() => {
  'use strict';

  // Lightweight tokenizer for phishing detection
  class SimpleTokenizer {
    constructor() {
      // Common phishing-related vocabulary
      this.vocab = {
        '[PAD]': 0, '[UNK]': 1, '[CLS]': 2, '[SEP]': 3,
        'verify': 4, 'account': 5, 'suspended': 6, 'urgent': 7,
        'click': 8, 'here': 9, 'immediately': 10, 'confirm': 11,
        'identity': 12, 'password': 13, 'reset': 14, 'update': 15,
        'payment': 16, 'security': 17, 'alert': 18, 'unusual': 19,
        'activity': 20, 'login': 21, 'secure': 22, 'bank': 23,
        'credit': 24, 'card': 25, 'expire': 26, 'limited': 27,
        'time': 28, 'offer': 29, 'prize': 30, 'winner': 31,
        'congratulations': 32, 'claim': 33, 'now': 34, 'act': 35,
        'fast': 36, 'warning': 37, 'blocked': 38, 'locked': 39,
        'unauthorized': 40, 'access': 41, 'detected': 42, 'fraud': 43
      };
      this.maxLength = 128;
    }

    /**
     * Simple word-level tokenization
     */
    tokenize(text) {
      if (!text) return [];
      
      // Lowercase and split
      const words = text.toLowerCase()
        .replace(/[^\w\s]/g, ' ')
        .split(/\s+/)
        .filter(w => w.length > 0);
      
      return words;
    }

    /**
     * Convert tokens to IDs
     */
    encode(text) {
      const tokens = this.tokenize(text);
      
      // Add [CLS] at start
      const ids = [this.vocab['[CLS]']];
      
      // Convert tokens to IDs
      for (let i = 0; i < Math.min(tokens.length, this.maxLength - 2); i++) {
        const token = tokens[i];
        const id = this.vocab[token] || this.vocab['[UNK]'];
        ids.push(id);
      }
      
      // Add [SEP] at end
      ids.push(this.vocab['[SEP]']);
      
      // Pad to maxLength
      while (ids.length < this.maxLength) {
        ids.push(this.vocab['[PAD]']);
      }
      
      return ids.slice(0, this.maxLength);
    }
  }

  // Lightweight rule-based model (fallback if ONNX not available)
  class RuleBasedModel {
    constructor() {
      this.phishingPatterns = [
        /verify.*account/i,
        /account.*suspended/i,
        /urgent.*action/i,
        /click.*immediately/i,
        /confirm.*identity/i,
        /reset.*password/i,
        /unusual.*activity/i,
        /update.*payment/i,
        /limited.*time/i,
        /act.*now/i,
        /claim.*prize/i,
        /you.*won/i,
        /congratulations/i,
        /security.*alert/i,
        /unauthorized.*access/i
      ];

      // Email/SMS-specific patterns
      this.emailPhishingPatterns = [
        /dear\s+(customer|user|member)/i,
        /verify\s+your\s+(email|account|identity)/i,
        /suspended\s+account/i,
        /unusual\s+sign-in\s+activity/i,
        /confirm\s+your\s+identity/i,
        /update\s+billing\s+information/i,
        /payment\s+(failed|declined|issue)/i,
        /refund\s+pending/i,
        /package\s+(delivery|waiting)/i,
        /tax\s+refund/i,
        /account\s+will\s+be\s+(closed|terminated)/i,
        /click\s+here\s+to\s+(verify|confirm|update)/i
      ];

      // Messaging-specific patterns
      this.messagePhishingPatterns = [
        /won\s+\$?\d+/i,
        /claim\s+your\s+(prize|reward|gift)/i,
        /free\s+(money|gift|iphone)/i,
        /congratulations.*winner/i,
        /urgent.*respond/i,
        /otp.*\d{4,6}/i,
        /verification\s+code/i,
        /bank.*verify/i,
        /crypto.*wallet/i,
        /investment.*opportunity/i
      ];

      this.suspiciousKeywords = [
        'verify', 'urgent', 'suspended', 'immediately', 'confirm',
        'identity', 'reset', 'password', 'unusual', 'activity',
        'update', 'payment', 'limited', 'time', 'prize', 'winner',
        'claim', 'congratulations', 'act', 'now', 'alert', 'warning',
        'blocked', 'locked', 'unauthorized', 'fraud'
      ];

      // Impersonation indicators
      this.impersonationKeywords = [
        'paypal', 'amazon', 'netflix', 'apple', 'microsoft',
        'google', 'facebook', 'instagram', 'bank', 'irs',
        'fedex', 'ups', 'dhl', 'usps', 'delivery'
      ];
    }

    /**
     * Calculate phishing score based on rules
     */
    predict(text, features) {
      if (!text) return 0.0;

      let score = 0.0;
      const textLower = text.toLowerCase();

      // Pattern matching (high weight)
      let patternMatches = 0;
      for (const pattern of this.phishingPatterns) {
        if (pattern.test(text)) {
          patternMatches++;
        }
      }
      score += patternMatches * 0.15;

      // Email-specific patterns
      let emailPatternMatches = 0;
      for (const pattern of this.emailPhishingPatterns) {
        if (pattern.test(text)) {
          emailPatternMatches++;
        }
      }
      score += emailPatternMatches * 0.12;

      // Messaging-specific patterns
      let messagePatternMatches = 0;
      for (const pattern of this.messagePhishingPatterns) {
        if (pattern.test(text)) {
          messagePatternMatches++;
        }
      }
      score += messagePatternMatches * 0.12;

      // Impersonation detection
      let impersonationCount = 0;
      for (const keyword of this.impersonationKeywords) {
        if (textLower.includes(keyword)) {
          impersonationCount++;
        }
      }
      if (impersonationCount > 0) {
        score += 0.15;
      }

      // Keyword density
      let keywordCount = 0;
      for (const keyword of this.suspiciousKeywords) {
        const regex = new RegExp(keyword, 'gi');
        const matches = text.match(regex);
        if (matches) {
          keywordCount += matches.length;
        }
      }
      const keywordDensity = keywordCount / Math.max(text.split(/\s+/).length, 1);
      score += Math.min(keywordDensity * 2, 0.3);

      // Feature-based scoring
      if (features) {
        if (features.password_fields > 0) score += 0.1;
        if (features.hidden_inputs > 2) score += 0.08;
        if (features.external_links > 5) score += 0.1;
        if (features.long_url) score += 0.05;
        if (features.excessive_subdomains) score += 0.08;
        if (features.suspicious_url_keywords) score += 0.07;
        if (features.iframe_count > 0) score += 0.06;
      }

      // Normalize to 0-1
      return Math.min(score, 1.0);
    }
  }

  // Local inference engine
  class LocalInferenceEngine {
    constructor() {
      this.tokenizer = new SimpleTokenizer();
      this.ruleBasedModel = new RuleBasedModel();
      this.onnxSession = null;
      this.modelLoaded = false;
      this.useONNX = false;
    }

    /**
     * Initialize the inference engine
     */
    async initialize() {
      console.log('[PhishGuard] Initializing local inference engine...');
      
      // For now, use rule-based model
      // ONNX integration can be added when model is available
      this.modelLoaded = true;
      console.log('[PhishGuard] Rule-based model ready');
      
      return true;
    }

    /**
     * Run local inference on text
     */
    async runInference(text, features = {}) {
      const startTime = performance.now();

      if (!this.modelLoaded) {
        await this.initialize();
      }

      try {
        // Use rule-based model
        const probability = this.ruleBasedModel.predict(text, features);
        
        // Convert probability to risk level
        let localRisk, localConfidence;
        
        if (probability >= 0.7) {
          localRisk = 'HIGH';
          localConfidence = probability;
        } else if (probability >= 0.4) {
          localRisk = 'MEDIUM';
          localConfidence = probability;
        } else {
          localRisk = 'LOW';
          localConfidence = 1 - probability;
        }

        const endTime = performance.now();
        const inferenceTime = endTime - startTime;

        console.log(`[PhishGuard] Local inference: ${localRisk} (${localConfidence.toFixed(2)}) in ${inferenceTime.toFixed(1)}ms`);

        return {
          local_risk: localRisk,
          local_confidence: parseFloat(localConfidence.toFixed(2)),
          inference_time_ms: parseFloat(inferenceTime.toFixed(1)),
          model_type: 'rule_based'
        };

      } catch (error) {
        console.error('[PhishGuard] Local inference error:', error);
        
        // Fallback to LOW risk on error
        return {
          local_risk: 'LOW',
          local_confidence: 0.5,
          inference_time_ms: 0,
          model_type: 'fallback',
          error: error.message
        };
      }
    }

    /**
     * Load ONNX model (for future use)
     */
    async loadONNXModel(modelPath) {
      try {
        if (typeof ort === 'undefined') {
          console.warn('[PhishGuard] ONNX Runtime not available');
          return false;
        }

        console.log('[PhishGuard] Loading ONNX model...');
        this.onnxSession = await ort.InferenceSession.create(modelPath);
        this.useONNX = true;
        console.log('[PhishGuard] ONNX model loaded successfully');
        return true;
      } catch (error) {
        console.warn('[PhishGuard] ONNX model load failed:', error);
        return false;
      }
    }

    /**
     * Run ONNX inference (for future use)
     */
    async runONNXInference(text) {
      if (!this.onnxSession) {
        throw new Error('ONNX model not loaded');
      }

      // Tokenize input
      const inputIds = this.tokenizer.encode(text);
      
      // Create tensor
      const inputTensor = new ort.Tensor('int64', BigInt64Array.from(inputIds.map(BigInt)), [1, inputIds.length]);
      
      // Run inference
      const feeds = { input_ids: inputTensor };
      const results = await this.onnxSession.run(feeds);
      
      // Extract probability
      const output = results.logits || results.output;
      const probability = output.data[1]; // Assuming binary classification
      
      return probability;
    }
  }

  // Create global instance
  const inferenceEngine = new LocalInferenceEngine();

  // Export to global scope
  window.phishGuardLocalAI = {
    initialize: () => inferenceEngine.initialize(),
    runInference: (text, features) => inferenceEngine.runInference(text, features),
    loadONNXModel: (path) => inferenceEngine.loadONNXModel(path)
  };

  // Auto-initialize
  inferenceEngine.initialize().catch(err => {
    console.error('[PhishGuard] Failed to initialize local AI:', err);
  });
})();
