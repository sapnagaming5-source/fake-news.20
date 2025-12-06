"""
Fake News Detection Module - Enhanced Version
Implements advanced source credibility verification and fact-checking
"""

import os
import re
import requests
from bs4 import BeautifulSoup
from typing import Dict, Optional, List, Tuple
import warnings
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import ssl
import socket
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False

try:
    import textstat
    TEXTSTAT_AVAILABLE = True
except ImportError:
    TEXTSTAT_AVAILABLE = False

# Import LSTM model
try:
    from lstm_model import LSTMFakeNewsModel
    LSTM_AVAILABLE = True
except ImportError:
    LSTM_AVAILABLE = False
    LSTMFakeNewsModel = None


class FakeNewsDetector:
    """Enhanced fake news detector with advanced source credibility verification"""
    
    def __init__(self):
        """Initialize the detector"""
        self.ai_provider = os.getenv("AI_PROVIDER", "").lower()  # 'gemini' or 'grok' or 'openai-compatible'
        self.ai_api_key = os.getenv("AI_API_KEY")
        self.ai_model = os.getenv("AI_MODEL", "")
        self.ai_endpoint = os.getenv("AI_ENDPOINT", "")  # override for custom endpoints
        self.suspicious_keywords = [
            'breaking', 'shocking', 'doctors hate', 'they don\'t want you to know',
            'secret', 'miracle', 'guaranteed', 'instant', 'one weird trick',
            'share this', 'viral', 'you won\'t believe', 'click here'
        ]
        
        # Comprehensive trusted publisher whitelist
        self.trusted_domains = {
            # Major International News
            'bbc.com', 'bbc.co.uk', 'reuters.com', 'ap.org', 'apnews.com',
            'nytimes.com', 'theguardian.com', 'washingtonpost.com', 'wsj.com',
            'npr.org', 'pbs.org', 'cnn.com', 'abcnews.go.com', 'cbsnews.com',
            'aljazeera.com', 'aljazeera.net', 'dw.com', 'france24.com',
            
            # US Major Newspapers
            'latimes.com', 'chicagotribune.com', 'bostonglobe.com', 'usatoday.com',
            'usnews.com', 'time.com', 'newsweek.com', 'theatlantic.com',
            
            # UK Major Newspapers
            'telegraph.co.uk', 'independent.co.uk', 'standard.co.uk',
            'ft.com', 'economist.com',
            
            # EU Major News
            'lemonde.fr', 'spiegel.de', 'repubblica.it', 'elpais.com',
            
            # India Major News
            'thehindu.com', 'indiatimes.com', 'hindustantimes.com',
            
            # Other Trusted Sources
            'scientificamerican.com', 'nature.com', 'science.org', 'nasa.gov',
            'who.int', 'un.org', 'europa.eu', 'gov.uk', 'gov.au', 'gov.ca'
        }
        
        # Known low-credibility/blacklisted domains
        self.blacklisted_domains = {
            # Add known fake news sites here
            # Example: 'fakenewssite.com'
        }
        
        # Initialize semantic model if available
        self.semantic_model = None
        self.semantic_available = SEMANTIC_AVAILABLE
        if self.semantic_available:
            try:
                self.semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self.semantic_available = False
        
        # Initialize LSTM model if available
        self.lstm_model = None
        if LSTM_AVAILABLE and LSTMFakeNewsModel:
            try:
                self.lstm_model = LSTMFakeNewsModel()
            except Exception as e:
                print(f"Could not initialize LSTM model: {e}")
                self.lstm_model = None
        

        # AI assessment availability
        self.ai_available = bool(self.ai_provider and self.ai_api_key)
    
    def normalize_url(self, url: str) -> Tuple[str, str]:
        """Normalize URL and extract domain"""
        if not url:
            return "", ""
        
        # Remove http/https and www
        url = url.lower().strip()
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r'^www\.', '', url)
        
        # Extract domain using tldextract if available
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            base_domain = extracted.domain
        else:
            # Fallback to basic parsing
            parsed = urlparse(f"http://{url}")
            domain = parsed.netloc or url.split('/')[0]
            base_domain = domain.split('.')[0] if '.' in domain else domain
        
        # Handle redirects and canonical URLs
        # (In production, you'd follow redirects here)
        canonical_mappings = {
            'bbc.com': 'bbc.co.uk',
            'bbc.co.uk': 'bbc.co.uk',
        }
        
        canonical = canonical_mappings.get(domain, domain)
        return canonical, base_domain
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, any]:
        """Check SSL certificate and organization info"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    org_name = ""
                    if cert and 'subject' in cert:
                        for item in cert['subject']:
                            if item[0][0] == 'organizationName':
                                org_name = item[0][1]
                                break
                    
                    return {
                        'has_ssl': True,
                        'organization': org_name,
                        'score_bonus': 5 if org_name else 0
                    }
        except:
            return {
                'has_ssl': False,
                'organization': None,
                'score_bonus': -15
            }
    
    def estimate_domain_age(self, domain: str) -> Dict[str, any]:
        """Estimate domain age (simplified - in production use WHOIS)"""
        # This is a simplified check - in production, use WHOIS API
        # For now, we'll check if domain looks established
        known_old_domains = {
            'bbc.co.uk', 'reuters.com', 'ap.org', 'nytimes.com',
            'theguardian.com', 'washingtonpost.com'
        }
        
        if domain in known_old_domains:
            return {'age_years': 20, 'score_bonus': 10}
        
        # Check for common patterns that suggest new domains
        suspicious_patterns = ['news', 'info', 'blog', 'site']
        if any(pattern in domain for pattern in suspicious_patterns):
            return {'age_years': 1, 'score_bonus': 0}
        
        # Default assumption
        return {'age_years': 3, 'score_bonus': 0}
    
    def extract_author_metadata(self, text: str, soup: BeautifulSoup = None) -> Dict[str, any]:
        """Extract author information from article"""
        author_name = None
        author_found = False
        
        # Try to find author in HTML metadata
        if soup:
            # Check common meta tags
            author_meta = soup.find('meta', {'name': re.compile('author', re.I)}) or \
                         soup.find('meta', {'property': 'article:author'}) or \
                         soup.find('span', {'class': re.compile('author|byline', re.I)})
            
            if author_meta:
                author_name = author_meta.get('content') or author_meta.get_text()
                author_found = True
        
        # Check text for byline patterns
        if not author_found:
            byline_patterns = [
                r'by\s+([A-Z][a-z]+\s+[A-Z][a-z]+)',
                r'author[:\s]+([A-Z][a-z]+\s+[A-Z][a-z]+)',
                r'written by\s+([A-Z][a-z]+\s+[A-Z][a-z]+)'
            ]
            
            for pattern in byline_patterns:
                match = re.search(pattern, text[:500], re.I)
                if match:
                    author_name = match.group(1)
                    author_found = True
                    break
        
        score_bonus = 0
        if author_found and author_name:
            # Check if author name looks real (has space, proper capitalization)
            if ' ' in author_name and len(author_name.split()) >= 2:
                score_bonus = 8
            else:
                score_bonus = 3
        else:
            score_bonus = -5
        
        return {
            'author': author_name,
            'found': author_found,
            'score_bonus': score_bonus
        }
    
    def check_fact_checking_apis(self, text: str, url: str) -> Dict[str, any]:
        """Check fact-checking APIs (simplified - requires API keys in production)"""
        # Extract key claims from text (simplified)
        sentences = re.split(r'[.!?]+', text)
        key_claims = [s.strip() for s in sentences[:5] if len(s.strip()) > 20]
        
        # In production, integrate with:
        # - Google Fact Check Tools API
        # - PolitiFact API
        # - Snopes API
        # - FactCheck.org API
        
        # For now, return neutral result
        # In production, make API calls here
        fact_check_result = {
            'checked': False,
            'verdict': None,  # 'true', 'false', 'mixed', None
            'source': None,
            'score_bonus': 0
        }
        
        # Simulated check - in production, replace with actual API calls
        # For now, return placeholder
        return {
            'checked': False,
            'verdict': None,
            'score_bonus': 0,
            'message': 'Fact checking APIs not configured'
        }

        return {
            'supported': False,
            'verdict': None,
            'score': None,
            'explanation': 'Provider not recognized'
        }
    
    def semantic_cross_verification(self, text: str) -> Dict[str, any]:
        """Check semantic similarity with credible news articles"""
        if not self.semantic_available or not self.semantic_model:
            return {
                'verified': False,
                'similarity_score': 0,
                'score_bonus': 0,
                'message': 'Semantic verification not available'
            }
        
        try:
            # Extract key claims (first few sentences)
            sentences = re.split(r'[.!?]+', text)
            key_text = ' '.join(sentences[:3])
            
            # In production, compare against a database of credible articles
            # For now, we'll do a simplified check
            
            # Example credible article snippets (in production, use a vector database)
            credible_snippets = [
                "The World Health Organization announced today that vaccination rates have increased globally",
                "Scientists have published new research findings in peer-reviewed journals",
                "Government officials released an official statement regarding the policy changes"
            ]
            
            if not key_text:
                return {
                    'verified': False,
                    'similarity_score': 0,
                    'score_bonus': 0
                }
            
            # Calculate embeddings
            query_embedding = self.semantic_model.encode([key_text])
            snippet_embeddings = self.semantic_model.encode(credible_snippets)
            
            # Calculate cosine similarity
            similarities = np.dot(query_embedding, snippet_embeddings.T)[0]
            max_similarity = float(np.max(similarities))
            
            score_bonus = 0
            verified = False
            
            if max_similarity >= 0.78:
                verified = True
                if max_similarity >= 0.85:
                    score_bonus = 25  # Multiple confirmations
                else:
                    score_bonus = 15  # Single confirmation
            
            return {
                'verified': verified,
                'similarity_score': round(max_similarity, 3),
                'score_bonus': score_bonus,
                'message': f'Semantic similarity: {max_similarity:.2f}'
            }
        except Exception as e:
            return {
                'verified': False,
                'similarity_score': 0,
                'score_bonus': 0,
                'message': f'Error in semantic verification: {str(e)}'
            }
    
    def check_source_authentication(self, source_name: str, url: str) -> Dict[str, any]:
        """
        Factor 3: Source Authentication (Is the source who they say they are?)
        Verifies if the claimed source name matches the article URL.
        """
        score = 50  # Start neutral
        factors = []
        is_authenticated = False
        match_type = "none"

        # Domain mappings for known sources (Validation Database)
        # This maps common names to their official domains
        source_domain_map = {
            'bbc': ['bbc.com', 'bbc.co.uk'],
            'bbc news': ['bbc.com', 'bbc.co.uk'],
            'cnn': ['cnn.com', 'edition.cnn.com'],
            'reuters': ['reuters.com'],
            'ap': ['ap.org', 'apnews.com'],
            'new york times': ['nytimes.com'],
            'nytimes': ['nytimes.com'],
            'the guardian': ['theguardian.com'],
            'washington post': ['washingtonpost.com'],
            'fox news': ['foxnews.com'],
            # Add more as needed
        }

        if not source_name:
             return {
                'score': 0,
                'is_authenticated': False,
                'status': 'missing',
                'factors': ['Source name not provided - cannot authenticate source identity']
            }

        # Normalize inputs
        norm_source = source_name.lower().strip()
        
        # If we have a URL, check if it matches the source name
        if url:
            normalized_url_domain, base_dom = self.normalize_url(url)
            
            # 1. Direct Domain Match Check
            # Does the source name appear in the domain? (e.g. source="CNN", url="cnn.com")
            if norm_source in normalized_url_domain or norm_source.replace(" ", "") in normalized_url_domain:
                score = 80
                is_authenticated = True
                match_type = "partial_name_match"
                factors.append(f"Source name '{source_name}' matches URL domain '{normalized_url_domain}'")

            # 2. Strict Database Check
            # Check if we know this source and if the URL is its official one
            known_domains = source_domain_map.get(norm_source)
            if known_domains:
                # We know this source!
                if any(d in normalized_url_domain for d in known_domains):
                    score = 100
                    is_authenticated = True
                    match_type = "verified_official"
                    factors.append(f"AUTHENTICATED: URL matches official domain for {source_name}")
                else:
                    # Impersonation Check! Source is known, but URL is not its official one
                    score = 0
                    is_authenticated = False
                    match_type = "impersonation_risk"
                    factors.append(f"WARNING: Claimed source is '{source_name}' but URL '{normalized_url_domain}' does not match official records")
            
            # 3. URL provided but no match found
            elif not is_authenticated:
                score = 40
                factors.append(f"Source name '{source_name}' could not be verified against URL '{normalized_url_domain}'")
        
        else:
            # Source provided but NO URL
            score = 30
            factors.append("Source name provided but no URL to verify it against (Unauthenticated)")

        return {
            'score': score,
            'is_authenticated': is_authenticated,
            'match_type': match_type,
            'factors': factors
        }

    def analyze_domain_trust(self, url: str) -> Dict[str, any]:
        """
        Factor 2: URL/Domain Analysis (Is the domain trusted?)
        """
        score = 50
        factors = []
        is_trusted = False
        is_blacklisted = False
        
        if not url:
             return {
                'score': 0,
                'is_trusted': False,
                'factors': ['No URL provided for domain analysis']
            }

        normalized_domain, base_domain = self.normalize_url(url)
        
        # Check whitelist
        if normalized_domain in self.trusted_domains:
            is_trusted = True
            score = 100
            factors.append(f"Domain '{normalized_domain}' is in Trusted Publishers list")
        
        # Check blacklist
        elif normalized_domain in self.blacklisted_domains:
            is_blacklisted = True
            score = 0
            factors.append(f"Domain '{normalized_domain}' is BLACKLISTED")
        
        else:
            # Unknown domain analysis
            ssl_info = self.check_ssl_certificate(normalized_domain)
            age_info = self.estimate_domain_age(normalized_domain)
            
            # Base score for unknown
            score = 50 
            
            if ssl_info['has_ssl']:
                score += 10
                factors.append("SSL Certificate Valid")
            else:
                score -= 20
                factors.append("No Valid SSL Certificate")
                
            if age_info['age_years'] > 5:
                score += 10
                factors.append("Domain is established (>5 years)")
            elif age_info['age_years'] < 1:
                score -= 20
                factors.append("Domain is very new (<1 year)")

        return {
            'score': max(0, min(100, score)),
            'is_trusted': is_trusted,
            'is_blacklisted': is_blacklisted,
            'domain': normalized_domain,
            'factors': factors
        }

    def analyze_language_patterns(self, text: str, is_trusted: bool = False) -> Dict[str, any]:
        """Analyze language patterns with reduced penalties for trusted sources"""
        score = 50  # Start neutral
        factors = []
        max_penalty = -10 if is_trusted else -50  # Limit penalties for trusted sources
        
        text_lower = text.lower()
        
        # Check for suspicious keywords
        suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        if suspicious_count > 0:
            penalty = min(suspicious_count * 5, abs(max_penalty))
            score -= penalty
            factors.append(f"Found {suspicious_count} suspicious marketing/sensationalist phrases")
        
        # Check for excessive capitalization
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        if caps_ratio > 0.3:
            penalty = min(10, abs(max_penalty))
            score -= penalty
            factors.append("Excessive use of capital letters (common in fake news)")
        
        # Check for excessive exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count > len(text) / 100:
            penalty = min(8, abs(max_penalty))
            score -= penalty
            factors.append("Excessive exclamation marks")
        
        # Check readability
        if TEXTSTAT_AVAILABLE:
            try:
                flesch_score = textstat.flesch_reading_ease(text[:1000]) if len(text) > 0 else 50
                if flesch_score < 20 or flesch_score > 90:
                    penalty = min(5, abs(max_penalty))
                    score -= penalty
                    factors.append("Unusual readability score (may indicate manipulation)")
            except:
                pass
        
        # Check for emotional language
        emotional_words = ['amazing', 'incredible', 'unbelievable', 'shocking', 'outrageous']
        emotional_count = sum(1 for word in emotional_words if word in text_lower)
        if emotional_count > 3:
            penalty = min(8, abs(max_penalty))
            score -= penalty
            factors.append("Excessive emotional language")
        
        # Ensure minimum score for trusted sources
        if is_trusted:
            score = max(score, 60)
        
        return {
            'score': min(100, max(0, score)),
            'factors': factors
        }
    
    def check_content_quality(self, text: str, is_trusted: bool = False) -> Dict[str, any]:
        """Check content quality with reduced penalties for trusted sources"""
        score = 50
        factors = []
        max_penalty = -10 if is_trusted else -50  # Limit penalties for trusted sources
        
        if not text or len(text.strip()) < 50:
            return {
                'score': 0,
                'factors': ['Article text is too short or empty']
            }
        
        # Check length
        word_count = len(text.split())
        if word_count < 100:
            penalty = min(20, abs(max_penalty))
            score -= penalty
            factors.append("Article is very short (may lack detail)")
        elif word_count > 2000:
            score += 10
            factors.append("Article has substantial length")
        
        # Check for proper sentence structure
        sentences = re.split(r'[.!?]+', text)
        avg_sentence_length = word_count / len(sentences) if sentences else 0
        
        if avg_sentence_length < 5 or avg_sentence_length > 30:
            penalty = min(10, abs(max_penalty))
            score -= penalty
            factors.append("Unusual sentence structure")
        else:
            score += 5
            factors.append("Normal sentence structure")
        
        # Check for citations or references
        if any(word in text.lower() for word in ['according to', 'study', 'research', 'source', 'cited']):
            score += 15
            factors.append("Article mentions sources or citations")
        
        # Check for quotes
        quote_count = text.count('"') + text.count("'")
        if quote_count > 4:
            score += 10
            factors.append("Article includes quotes (may indicate reporting)")
        
        # Ensure minimum score for trusted sources
        if is_trusted:
            score = max(score, 60)
        
        return {
            'score': min(100, max(0, score)),
            'factors': factors
        }

    def analyze_article_text_content(self, text: str) -> Dict[str, any]:
        """
        Factor 1: Text Content Analysis (Real-time pattern checking)
        """
        if not text:
            return {'score': 0, 'factors': ['No text provided']}

        # Reuse existing language pattern logic but return cleaner struct
        lang_analysis = self.analyze_language_patterns(text, is_trusted=False) # Do NOT protect trusted sources here, check text objectively
        quality_analysis = self.check_content_quality(text, is_trusted=False)
        
        # Combine text factors
        combined_score = (lang_analysis['score'] + quality_analysis['score']) / 2
        
        factors = lang_analysis['factors'] + quality_analysis['factors']
        
        return {
            'score': combined_score,
            'factors': factors,
            'details': {
            'language': lang_analysis,
                'quality': quality_analysis
            }
        }

    def ai_assess_article(self, text: str, source: str, url: str) -> Dict[str, any]:
        """
        AI Assessment using Local LLM (OpenAI-Compatible / LM Studio)
        """
        provider = os.getenv('AI_PROVIDER', 'openai-compatible') # Default to local
        api_key = os.getenv('AI_API_KEY', 'lm-studio') # Default dummy key for local
        
        try:
            # Configuration
            model_name = os.getenv('AI_MODEL', 'grok-3-gemma3-4b-distilled')
            api_base = os.getenv('AI_ENDPOINT', 'http://127.0.0.1:1234/v1')
            api_url = f"{api_base}/chat/completions"
            
            # Prompt Construction
            system_prompt = (
                "You are an expert fact-check analyst. Analyze the provided news article.\n"
                "Return valid JSON ONLY with these keys:\n"
                "- verdict: 'True', 'Fake', 'Mixed', or 'Satire'\n"
                "- confidence_score: integer 0-100\n"
                "- reasoning: brief explanation (max 2 sentences)\n"
                "- key_flags: list of strings (flagging issues)\n"
                "Do not include markdown formatting like ```json."
            )
            
            user_prompt = (
                f"Source: {source}\n"
                f"URL: {url}\n"
                f"Text: {text[:3000]} (truncated)\n\n"
                "Analyze authenticity."
            )
            
            payload = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1, # Low temp for consistent JSON
                "max_tokens": 500
            }
            
            import requests
            # Standard OpenAI-format request
            response = requests.post(api_url, json=payload, headers={"Authorization": f"Bearer {api_key}"}, timeout=120)
            response.raise_for_status()
            
            data = response.json()
            raw_content = data['choices'][0]['message']['content']
            
            # Clean up potential markdown formatting from LLM
            clean_json = raw_content.replace('```json', '').replace('```', '').strip()
            
            import json
            try:
                ai_result = json.loads(clean_json)
                return {
                    'supported': True,
                    'verdict': ai_result.get('verdict', 'Unknown'),
                    'score': ai_result.get('confidence_score', 50),
                    'explanation': ai_result.get('reasoning', 'No reasoning provided.'),
                    'key_flags': ai_result.get('key_flags', [])
                }
            except json.JSONDecodeError:
                # Fallback: Try to find JSON-like structure if mixed with text
                import re
                match = re.search(r'\{.*\}', clean_json, re.DOTALL)
                if match:
                    try:
                        ai_result = json.loads(match.group(0))
                        return {
                            'supported': True,
                            'verdict': ai_result.get('verdict', 'Unknown'),
                            'score': ai_result.get('confidence_score', 50),
                            'explanation': ai_result.get('reasoning', 'Parsed from unstructured response.'),
                            'key_flags': ai_result.get('key_flags', [])
                        }
                    except:
                        pass
                        
                return {
                    'supported': True,
                    'verdict': 'Unknown',
                    'score': 50,
                    'explanation': f"Raw Output (Parse Failed): {raw_content[:200]}...",
                    'key_flags': ['JSON Parse Error']
                }

        except Exception as e:
            print(f"Local AI Error: {e}")
            return {
                'supported': False,
                'verdict': None,
                'score': None,
                'explanation': f"AI Connection Failed: {str(e)}",
                'key_flags': []
            }

    def analyze_article(self, text: str, source: str = "", url: str = "") -> Dict[str, any]:
        """
        Main Analysis Function - Enhanced with AI
        """
        
        # 1. Prepare Inputs
        if not text and url:
            extracted_text, soup = self.extract_text_from_url(url)
            if extracted_text:
                text = extracted_text
                
        # 2. Perform 3-Factor Analysis (Rule-Based)
        text_analysis = self.analyze_article_text_content(text)
        domain_analysis = self.analyze_domain_trust(url)
        auth_analysis = self.check_source_authentication(source, url)

        # 3. AI Assessment (Parallel Factor)
        ai_assessment = self.ai_assess_article(text, source, url)
        
        # 4. Calculate Final Score
        # If AI is available, it gets 50% weight, others get 50%
        
        active_factors = 0
        total_score_accum = 0
        
        # Rule based scores
        rule_score = 0
        rule_factors_count = 0
        
        if text:
            rule_score += text_analysis['score']
            rule_factors_count += 1
        if url:
            rule_score += domain_analysis['score']
            rule_factors_count += 1
        if source:
            rule_score += auth_analysis['score']
            rule_factors_count += 1
            
        avg_rule_score = rule_score / rule_factors_count if rule_factors_count > 0 else 0
        
        if ai_assessment['supported'] and ai_assessment['score'] is not None:
            # Weighted Model: AI (50%) + Rules (50%)
            # This gives the AI significant influence but keeps rules as a sanity check
            final_score = (avg_rule_score * 0.5) + (ai_assessment['score'] * 0.5)
            message = ai_assessment['explanation'] # Use AI explanation as primary message
        else:
            final_score = avg_rule_score
            message = "Rule-based analysis completed."

        # 5. Critical Logic Overrides
        
        # Impersonation is still critical veto
        is_impersonation = auth_analysis.get('match_type') == 'impersonation_risk'
        if is_impersonation:
            final_score = 0
            message = "CRITICAL: Source Authenticity Failed (Impersonation Detected). AI/Rules Overridden."
        
        # Blacklist is veto
        if domain_analysis.get('is_blacklisted'):
            final_score = 0
            message = "Domain is BLACKLISTED."

        # Determine Verdict
        if final_score >= 80:
            is_fake = False
            verdict = "Likely True"
            confidence = 0.9
        elif final_score >= 50:
            is_fake = False
            verdict = "Unverified / Mixed"
            confidence = 0.6
        else:
            is_fake = True
            verdict = "Likely Fake"
            confidence = 0.8
            
        return {
            'is_fake': is_fake,
            'score': round(final_score, 1),
            'confidence': confidence,
            'confidence_percent': round(confidence * 100, 1),
            'message': message,
            'breakdown': {
                'text_score': text_analysis['score'],
                'domain_score': domain_analysis['score'],
                'auth_score': auth_analysis['score'],
                'ai_score': ai_assessment.get('score', 0) if ai_assessment['supported'] else None
            },
            'details': {
                'text_analysis': text_analysis,
                'domain_analysis': domain_analysis,
                'auth_analysis': auth_analysis,
                'ai_analysis': ai_assessment
            }
        }
