#!/usr/bin/env python3
"""
Email Validator Streamlit App
A web interface for validating emails from CSV or Excel files.
"""

import streamlit as st
import pandas as pd
import re
import smtplib
import socket
import dns.resolver
from email.mime.text import MIMEText
from typing import List, Tuple, Dict
from pathlib import Path
import io
import time
import requests
import json
from urllib.parse import urlparse
import hashlib

class EmailValidator:
    def __init__(self, smtp_check=False, timeout=10, check_disposable=True, check_role_based=True):
        """
        Initialize EmailValidator with enhanced validation features
        
        Args:
            smtp_check (bool): Whether to perform SMTP validation
            timeout (int): Timeout for SMTP connections in seconds
            check_disposable (bool): Check for disposable email domains
            check_role_based (bool): Check for role-based email addresses
        """
        self.smtp_check = smtp_check
        self.timeout = timeout
        self.check_disposable = check_disposable
        self.check_role_based = check_role_based
        
        # Enhanced regex for RFC 5322 compliance
        self.email_regex = re.compile(
            r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*@'
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        )
        
        # Common disposable email domains (expandable list)
        self.disposable_domains = {
            '10minutemail.com', '10minutemail.net', '20minutemail.com', '2prong.com', '30minutemail.com',
            '33mail.com', '3d-painting.com', '4warding.com', '7tags.com', '9ox.net', 'aaathats3as.com',
            'abyssmail.com', 'afrobacon.com', 'ajaxapp.net', 'amilegit.com', 'amiri.net', 'amiriinc.com',
            'anonbox.net', 'anonymail.dk', 'anonymbox.com', 'antichef.com', 'antichef.net', 'antireg.ru',
            'antispam.de', 'antispammail.de', 'armyspy.com', 'azmeil.tk', 'baxomale.ht.cx', 'beefmilk.com',
            'bigstring.com', 'binkmail.com', 'bio-mance.com', 'blackmarket.to', 'bladesmail.net', 'bloatbox.com',
            'bobmail.info', 'bodhi.lawlita.com', 'bofthew.com', 'bootybay.de', 'boun.cr', 'bouncr.com',
            'breakthru.com', 'brefmail.com', 'brennendesreich.de', 'broadbandninja.com', 'bsnow.net',
            'bugmenot.com', 'bumpymail.com', 'bundes-liga.de', 'burnthespam.info', 'burstmail.info',
            'buyusedlibrarybooks.org', 'byom.de', 'c2.hu', 'cachedot.net', 'camera.al', 'cardboardfish.com',
            'cashette.com', 'caelestis.com', 'centermail.com', 'centermail.net', 'chammy.info', 'childsavetrust.org',
            'chogmail.com', 'choicemail1.com', 'clixser.com', 'cmail.net', 'cmail.org', 'coldemail.info',
            'cool.fr.nf', 'correo.blogos.net', 'cosmorph.com', 'courriel.fr.nf', 'courrieltemporaire.com',
            'crapmail.org', 'cust.in', 'cuvox.de', 'd3p.dk', 'dacoolest.com', 'dandikmail.com', 'dayrep.com',
            'dbunker.com', 'dcemail.com', 'deadaddress.com', 'deadspam.com', 'delikkt.de', 'despam.it',
            'despammed.com', 'devnullmail.com', 'dfgh.net', 'digitalsanctuary.com', 'dingbone.com',
            'discard.email', 'discardmail.com', 'discardmail.de', 'disposableaddress.com', 'disposableemailaddresses.com',
            'disposableinbox.com', 'dispose.it', 'disposeamail.com', 'disposemail.com', 'dispostable.com',
            'dm.ales.co', 'dodgeit.com', 'dodgit.com', 'dodgit.org', 'donemail.ru', 'dontreg.com',
            'dontsendmespam.de', 'drdrb.net', 'droplar.com', 'dropmail.me', 'duam.net', 'dudmail.com',
            'dump-email.info', 'dumpandjunk.com', 'dumpmail.de', 'dumpyemail.com', 'e-mail.com', 'e-mail.org',
            'e4ward.com', 'easytrashmail.com', 'ee1.pl', 'ee2.pl', 'eelmail.com', 'einrot.com', 'einrot.de',
            'emailgo.de', 'emailias.com', 'emailinfive.com', 'emailmiser.com', 'emailsensei.com', 'emailtemporanea.com',
            'emailtemporanea.net', 'emailtemporar.ro', 'emailtemporario.com.br', 'emailthe.net', 'emailtmp.com',
            'emailto.de', 'emailwarden.com', 'emailx.at.hm', 'emailxfer.com', 'emeil.in', 'emeil.ir',
            'emz.net', 'enterto.com', 'ephemail.net', 'etranquil.com', 'etranquil.net', 'etranquil.org',
            'evopo.com', 'explodemail.com', 'express.net.ua', 'eyepaste.com', 'fakeinbox.com', 'fakeinformation.com',
            'fakemail.fr', 'fakemailz.com', 'fammix.com', 'fansworldwide.de', 'fantasymail.de', 'fastacura.com',
            'fastchevy.com', 'fastchrysler.com', 'fastkawasaki.com', 'fastmazda.com', 'fastmitsubishi.com',
            'fastnissan.com', 'fastsubaru.com', 'fastsuzuki.com', 'fasttoyota.com', 'fastyamaha.com',
            'fatflap.com', 'fdfdsfds.com', 'fightbackspam.com', 'filzmail.com', 'fivemail.de', 'fixmail.tk',
            'fizmail.com', 'fleckens.hu', 'fly-ts.de', 'flyspam.com', 'footard.com', 'forgetmail.com',
            'fr33mail.info', 'frapmail.com', 'freebabysittercam.com', 'freeblabbermouths.com', 'freebulkmail.net',
            'freefall.or.id', 'freeletter.me', 'freemeil.ga', 'freemeil.gq', 'freemeil.ml', 'freemeil.tk',
            'freemium.de', 'freemlm.net', 'freeschmexy.com', 'freetemp.tk', 'freundin.ru', 'fromru.com',
            'front14.org', 'fuckingduh.com', 'fudgerub.com', 'fux0ringduh.com', 'fyii.de', 'garliclife.com',
            'gehensiemirnichtaufdensack.de', 'gelitik.in', 'get-mail.tk', 'get1mail.com', 'get2mail.fr',
            'getairmail.com', 'getmails.eu', 'getonemail.com', 'getonemail.net', 'girlsundertheinfluence.com',
            'gishpuppy.com', 'gmial.com', 'goemailgo.com', 'gotmail.com', 'gotmail.net', 'gotmail.org',
            'gotti.otherinbox.com', 'great-host.in', 'greensloth.com', 'grr.la', 'gsrv.co.uk', 'guerillamail.biz',
            'guerillamail.com', 'guerillamail.de', 'guerillamail.info', 'guerillamail.net', 'guerillamail.org',
            'guerrillamail.biz', 'guerrillamail.com', 'guerrillamail.de', 'guerrillamail.info', 'guerrillamail.net',
            'guerrillamail.org', 'guerrillamailblock.com', 'gustr.com', 'harakirimail.com', 'hat-geld.de',
            'hatespam.org', 'hellodream.mobi', 'herp.in', 'hidemail.de', 'hidzz.com', 'hmamail.com',
            'hochsitze.com', 'hopemail.biz', 'hot-mail.cf', 'hot-mail.ga', 'hot-mail.gq', 'hot-mail.ml',
            'hot-mail.tk', 'hotpop.com', 'hulapla.de', 'ichimail.ru', 'identity.com', 'ieatspam.eu',
            'ieatspam.info', 'ieh-mail.de', 'ikbenspamvrij.nl', 'imails.info', 'imgof.com', 'imstations.com',
            'inboxalias.com', 'inboxclean.com', 'inboxclean.org', 'infocom.zp.ua', 'instant-mail.de',
            'ip6.li', 'irish2me.com', 'iwi.net', 'jetable.com', 'jetable.fr.nf', 'jetable.net',
            'jetable.org', 'jnxjn.com', 'jourrapide.com', 'jsrsolutions.com', 'junk1e.com', 'kappa.ro',
            'kasmail.com', 'kaspop.com', 'keepmymail.com', 'killmail.com', 'killmail.net', 'kimsdisk.com',
            'kir.ch.tc', 'klassmaster.com', 'klzlk.com', 'koszmail.pl', 'kurzepost.de', 'l33r.eu',
            'labetteraverouge.at', 'lackmail.net', 'lags.us', 'lawlita.com', 'lazyinbox.com', 'letthemeatspam.com',
            'lhsdv.com', 'lifebyfood.com', 'link2mail.net', 'litedrop.com', 'lol.ovpn.to', 'lookugly.com',
            'lopl.co.cc', 'lortemail.dk', 'lr78.com', 'lroid.com', 'lukop.dk', 'm21.cc', 'mail.by',
            'mail.mezimages.net', 'mail.zp.ua', 'mail1a.de', 'mail21.cc', 'mail2rss.org', 'mail333.com',
            'mail4trash.com', 'mailbidon.com', 'mailblocks.com', 'mailbucket.org', 'mailcat.biz', 'mailcatch.com',
            'mailde.de', 'mailde.info', 'maildrop.cc', 'maildrop.cf', 'maildrop.ga', 'maildrop.gq',
            'maildrop.ml', 'maildrop.tk', 'maildx.com', 'maileater.com', 'mailed.ro', 'mailexpire.com',
            'mailfa.tk', 'mailforspam.com', 'mailfree.ga', 'mailfree.gq', 'mailfree.ml', 'mailfreeonline.com',
            'mailguard.me', 'mailhazard.com', 'mailhazard.us', 'mailhz.me', 'mailimate.com', 'mailin8r.com',
            'mailinater.com', 'mailinator.com', 'mailinator.net', 'mailinator.org', 'mailinator.us',
            'mailinator2.com', 'mailincubator.com', 'mailismagic.com', 'mailme.gq', 'mailme.ir', 'mailme.lv',
            'mailmetrash.com', 'mailmoat.com', 'mailms.com', 'mailnator.com', 'mailnesia.com', 'mailnull.com',
            'mailorg.org', 'mailpick.biz', 'mailrock.biz', 'mailscrap.com', 'mailshell.com', 'mailsiphon.com',
            'mailtemp.info', 'mailtome.de', 'mailtothis.com', 'mailtrash.net', 'mailtv.net', 'mailtv.tv',
            'mailzilla.com', 'mailzilla.org', 'makemetheking.com', 'manybrain.com', 'mbx.cc', 'mciek.com',
            'mega.zik.dj', 'meinspamschutz.de', 'meltmail.com', 'messagebeamer.de', 'mezimages.net',
            'mierdamail.com', 'migmail.pl', 'mintemail.com', 'mjukglass.nu', 'mobi.web.id', 'moburl.com',
            'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf', 'monumentmail.com', 'mt2009.com',
            'mt2014.com', 'mycard.net.ua', 'mycleaninbox.net', 'myemailboxy.com', 'mymail-in.net',
            'mymailoasis.com', 'mynetstore.de', 'mypacks.net', 'mypartyclip.de', 'myphantomemail.com',
            'myspaceinc.com', 'myspaceinc.net', 'myspaceinc.org', 'myspacepimpedup.com', 'myspamless.com',
            'mytempemail.com', 'mytempmail.com', 'mytrashmail.com', 'nabuma.com', 'neomailbox.com',
            'nepwk.com', 'nervmich.net', 'nervtmich.net', 'netmails.com', 'netmails.net', 'netzidiot.de',
            'neverbox.com', 'nice-4u.com', 'nincsmail.com', 'nincsmail.hu', 'nnh.com', 'no-spam.ws',
            'nobugmail.com', 'nobulk.com', 'noclickemail.com', 'nogmailspam.info', 'nomail.xl.cx',
            'nomail2me.com', 'nomorespamemails.com', 'nonemail.ru', 'nonspam.eu', 'nonspammer.de',
            'noref.in', 'nospam.ze.tc', 'nospam4.us', 'nospamfor.us', 'nospammail.net', 'nospamthanks.info',
            'notmailinator.com', 'nowmymail.com', 'nurfuerspam.de', 'nus.edu.sg', 'nwldx.com', 'objectmail.com',
            'obobbo.com', 'odnorazovoe.ru', 'ohaaa.de', 'olypmall.ru', 'oneoffemail.com', 'onewaymail.com',
            'onlatedotcom.info', 'online.ms', 'oopi.org', 'opayq.com', 'ordinaryamerican.net',
            'otherinbox.com', 'ovpn.to', 'owlpic.com', 'pancakemail.com', 'paplease.com', 'pcusers.otherinbox.com',
            'pjkl.com', 'plexolan.de', 'poczta.onet.pl', 'politikerclub.de', 'poofy.org', 'pookmail.com',
            'postacin.com', 'privacy.net', 'privatdemail.net', 'proxymail.eu', 'prtnx.com', 'prtz.eu',
            'punkass.com', 'putthisinyourspamdatabase.com', 'pwrby.com', 'qq.com', 'quickinbox.com',
            'rcpt.at', 'reallymymail.com', 'realtyalerts.ca', 'receiveee.chickenkiller.com', 'receiveee.com',
            'recursor.net', 'regbypass.com', 'regbypass.comsafe-mail.net', 'rejectmail.com', 'rhyta.com',
            'rklips.com', 'rmqkr.net', 'royal.net', 'rppkn.com', 'rtrtr.com', 's0ny.net', 'safe-mail.net',
            'safetymail.info', 'safetypost.de', 'sandelf.de', 'saynotospams.com', 'schafmail.de',
            'schrott-email.de', 'secretemail.de', 'secure-mail.biz', 'selfdestructingmail.com',
            'sendspamhere.de', 'sharklasers.com', 'shieldemail.com', 'shiftmail.com', 'shitmail.me',
            'shitware.nl', 'shieldmail.com', 'shortmail.net', 'sibmail.com', 'sinnlos-mail.de',
            'skeefmail.com', 'slapsfromlastnight.com', 'slaskpost.se', 'slopsbox.com', 'slushmail.com',
            'smashmail.de', 'smellfear.com', 'snakemail.com', 'sneakemail.com', 'snkmail.com',
            'sofimail.com', 'sofort-mail.de', 'sogetthis.com', 'soodonims.com', 'spam.la', 'spam.su',
            'spam4.me', 'spamail.de', 'spambob.com', 'spambob.net', 'spambob.org', 'spambog.com',
            'spambog.de', 'spambog.ru', 'spambox.info', 'spambox.irishspringtours.com', 'spambox.us',
            'spamcannon.com', 'spamcannon.net', 'spamcon.org', 'spamcorptastic.com', 'spamcowboy.com',
            'spamcowboy.net', 'spamcowboy.org', 'spamday.com', 'spamex.com', 'spamfree24.com',
            'spamfree24.de', 'spamfree24.eu', 'spamfree24.net', 'spamfree24.org', 'spamgourmet.com',
            'spamgourmet.net', 'spamgourmet.org', 'spamherelots.com', 'spamhereplease.com', 'spamhole.com',
            'spami.spam.co.za', 'spaminator.de', 'spamkill.info', 'spaml.com', 'spaml.de', 'spammotel.com',
            'spamobox.com', 'spamoff.de', 'spamslicer.com', 'spamspot.com', 'spamstack.net', 'spamthis.co.uk',
            'spamthisplease.com', 'spamtrail.com', 'spamtroll.net', 'speed.1s.fr', 'srilankahotel.com',
            'ss.ee', 'startkeys.com', 'stinkefinger.net', 'stop-my-spam.com', 'stuffmail.de',
            'super-auswahl.de', 'supergreatmail.com', 'supermailer.jp', 'superrito.com', 'superstachel.de',
            'suremail.info', 'talkinator.com', 'tafmail.com', 'teewars.org', 'teleworm.com', 'teleworm.us',
            'temp-mail.org', 'temp-mail.ru', 'tempalias.com', 'tempe-mail.com', 'tempemail.biz',
            'tempemail.com', 'tempinbox.co.uk', 'tempinbox.com', 'tempmail.eu', 'tempmaildemo.com',
            'tempmailer.com', 'tempmailer.de', 'tempomail.fr', 'temporarily.de', 'temporarioemail.com.br',
            'temporaryemail.net', 'temporaryforwarding.com', 'temporaryinbox.com', 'temporarymailaddress.com',
            'tempsky.com', 'tempymail.com', 'thanksnospam.info', 'thankyou2010.com', 'thecloudindex.com',
            'thisisnotmyrealemail.com', 'thismail.net', 'throam.com', 'thrott.com', 'throwawayemailaddresses.com',
            'tilien.com', 'tittbit.in', 'tizi.com', 'tmailinator.com', 'toomail.biz', 'topranklist.de',
            'tradermail.info', 'trash-amil.com', 'trash-mail.at', 'trash-mail.com', 'trash-mail.de',
            'trash2009.com', 'trash2010.com', 'trash2011.com', 'trashdevil.com', 'trashemail.de',
            'trashmail.at', 'trashmail.com', 'trashmail.de', 'trashmail.me', 'trashmail.net',
            'trashmail.org', 'trashmail.ws', 'trashmailer.com', 'trashymail.com', 'trashymail.net',
            'traszmail.de', 'trayna.com', 'trbvm.com', 'trialmail.de', 'tryalert.com', 'turual.com',
            'twinmail.de', 'tyldd.com', 'uggsrock.com', 'umail.net', 'upliftnow.com', 'uplipht.com',
            'uroid.com', 'us.af', 'venompen.com', 'verlass-mich-nicht.de', 'veryrealemail.com',
            'vidchart.com', 'viditag.com', 'viewcastmedia.com', 'viewcastmedia.net', 'viewcastmedia.org',
            'vomoto.com', 'vorga.com', 'votiputox.org', 'vubby.com', 'walala.org', 'walkmail.net',
            'webemail.me', 'webm4il.info', 'webuser.in', 'wh4f.org', 'whatiaas.com', 'whatpaas.com',
            'whatsaas.com', 'whopy.com', 'willhackforfood.biz', 'willselldrugs.com', 'winemaven.info',
            'wronghead.com', 'wuzup.net', 'wuzupmail.net', 'wwwnew.eu', 'x.ip6.li', 'xagloo.com',
            'xemaps.com', 'xents.com', 'xmaily.com', 'xoxy.net', 'yapped.net', 'yep.it', 'yogamaven.com',
            'yomail.info', 'yopmail.com', 'yopmail.fr', 'yopmail.net', 'yourdomain.com', 'ypmail.webredirect.org',
            'yuurok.com', 'zehnminutenmail.de', 'zippymail.info', 'zoaxe.com', 'zoemail.org', 'zomg.info'
        }
        
        # Role-based email prefixes
        self.role_based_prefixes = {
            'admin', 'administrator', 'abuse', 'billing', 'contact', 'customer', 'info', 'inquiry', 
            'mail', 'mailman', 'marketing', 'noreply', 'no-reply', 'noreply', 'orders', 'postmaster', 
            'privacy', 'public', 'root', 'sales', 'security', 'service', 'support', 'tech', 'webmaster',
            'help', 'helpdesk', 'office', 'press', 'social', 'accounts', 'hr', 'legal', 'team',
            'subscribe', 'unsubscribe', 'newsletter', 'news', 'media', 'careers', 'jobs', 'feedback'
        }
        
        # Cache for domain validations to improve performance
        self.domain_cache = {}
        self.mx_cache = {}
    
    def validate_email_format(self, email: str) -> Tuple[bool, str]:
        """
        Enhanced email format validation using RFC 5322 compliant regex
        
        Args:
            email (str): Email address to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, validation_detail)
        """
        if not email or not isinstance(email, str):
            return False, "Empty or invalid email type"
        
        email = email.strip()
        
        # Basic length checks
        if len(email) > 254:
            return False, "Email too long (>254 characters)"
        
        if '@' not in email:
            return False, "Missing @ symbol"
        
        try:
            local, domain = email.rsplit('@', 1)
        except ValueError:
            return False, "Invalid email format"
        
        # Local part validation
        if len(local) > 64:
            return False, "Local part too long (>64 characters)"
        
        if len(local) == 0:
            return False, "Empty local part"
        
        # Domain part validation
        if len(domain) > 253:
            return False, "Domain too long (>253 characters)"
        
        if len(domain) == 0:
            return False, "Empty domain"
        
        # Check for consecutive dots
        if '..' in email:
            return False, "Consecutive dots not allowed"
        
        # Check if starts or ends with dot
        if local.startswith('.') or local.endswith('.'):
            return False, "Local part cannot start or end with dot"
        
        # Regex validation
        if not self.email_regex.match(email.lower()):
            return False, "Invalid email format"
        
        return True, "Valid format"
    
    def check_domain_exists(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain exists using DNS lookup
        
        Args:
            domain (str): Domain to check
            
        Returns:
            Tuple[bool, str]: (exists, detail)
        """
        if domain in self.domain_cache:
            return self.domain_cache[domain]
        
        try:
            # Try to resolve A record
            dns.resolver.resolve(domain, 'A')
            result = (True, "Domain exists")
            self.domain_cache[domain] = result
            return result
        except dns.resolver.NXDOMAIN:
            result = (False, "Domain does not exist")
            self.domain_cache[domain] = result
            return result
        except Exception as e:
            result = (False, f"DNS lookup failed: {str(e)[:50]}")
            self.domain_cache[domain] = result
            return result
    
    def get_mx_record(self, domain: str) -> Tuple[bool, str, str]:
        """
        Enhanced MX record validation
        
        Args:
            domain (str): Domain to check
            
        Returns:
            Tuple[bool, str, str]: (has_mx, mx_record, detail)
        """
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                # Get the MX record with lowest preference (highest priority)
                mx_record = min(mx_records, key=lambda x: x.preference)
                mx_host = str(mx_record.exchange).rstrip('.')
                result = (True, mx_host, f"MX record found: {mx_host}")
                self.mx_cache[domain] = result
                return result
            else:
                result = (False, None, "No MX records found")
                self.mx_cache[domain] = result
                return result
        except dns.resolver.NXDOMAIN:
            result = (False, None, "Domain does not exist")
            self.mx_cache[domain] = result
            return result
        except Exception as e:
            result = (False, None, f"MX lookup failed: {str(e)[:50]}")
            self.mx_cache[domain] = result
            return result
    
    def check_disposable_domain(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain is a known disposable email provider
        
        Args:
            domain (str): Domain to check
            
        Returns:
            Tuple[bool, str]: (is_disposable, detail)
        """
        domain_lower = domain.lower()
        if domain_lower in self.disposable_domains:
            return True, f"Disposable email domain: {domain}"
        return False, "Not a known disposable domain"
    
    def check_role_based_email(self, email: str) -> Tuple[bool, str]:
        """
        Check if email is role-based (not personal)
        
        Args:
            email (str): Email address to check
            
        Returns:
            Tuple[bool, str]: (is_role_based, detail)
        """
        try:
            local_part = email.split('@')[0].lower()
            
            # Remove common separators and check base
            clean_local = local_part.replace('.', '').replace('-', '').replace('_', '')
            
            for role_prefix in self.role_based_prefixes:
                if clean_local.startswith(role_prefix) or clean_local == role_prefix:
                    return True, f"Role-based email: {role_prefix}"
            
            return False, "Not role-based"
        except:
            return False, "Could not determine"
    
    def check_catch_all_domain(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain has catch-all email configuration
        
        Args:
            domain (str): Domain to check
            
        Returns:
            Tuple[bool, str]: (is_catch_all, detail)
        """
        if not self.smtp_check:
            return False, "SMTP check disabled"
        
        # Generate a random email that should not exist
        random_local = f"nonexistent{hashlib.md5(domain.encode()).hexdigest()[:8]}"
        test_email = f"{random_local}@{domain}"
        
        try:
            has_mx, mx_record, _ = self.get_mx_record(domain)
            if not has_mx:
                return False, "No MX record"
            
            # Try SMTP validation with the fake email
            server = smtplib.SMTP(timeout=self.timeout)
            server.connect(mx_record, 25)
            server.helo('validator.com')
            server.mail('test@validator.com')
            
            code, message = server.rcpt(test_email)
            server.quit()
            
            if code == 250:
                return True, "Possible catch-all domain"
            else:
                return False, "Not catch-all"
                
        except Exception:
            return False, "Could not determine"
    
    def smtp_validate(self, email: str) -> Tuple[bool, str]:
        """
        Enhanced SMTP validation with detailed responses
        
        Args:
            email (str): Email address to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, detail)
        """
        format_valid, format_detail = self.validate_email_format(email)
        if not format_valid:
            return False, format_detail
        
        domain = email.split('@')[1]
        has_mx, mx_record, mx_detail = self.get_mx_record(domain)
        
        if not has_mx:
            return False, mx_detail
        
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(timeout=self.timeout)
            server.connect(mx_record, 25)
            server.helo('validator.com')
            server.mail('test@validator.com')
            
            # Check if email exists
            code, message = server.rcpt(email)
            server.quit()
            
            if code == 250:
                return True, "SMTP verification successful"
            elif code == 550:
                return False, "Email address not found (550)"
            elif code == 551:
                return False, "User not local (551)"
            elif code == 552:
                return False, "Mailbox full (552)"
            elif code == 553:
                return False, "Invalid email format (553)"
            else:
                return False, f"SMTP error code: {code}"
            
        except smtplib.SMTPServerDisconnected:
            return False, "SMTP server disconnected"
        except smtplib.SMTPRecipientsRefused:
            return False, "Email address refused by server"
        except socket.timeout:
            return False, "SMTP connection timeout"
        except Exception as e:
            return False, f"SMTP validation failed: {str(e)[:50]}"
    
    def validate_email(self, email: str) -> Tuple[bool, str, Dict]:
        """
        Comprehensive email validation with detailed analysis
        
        Args:
            email (str): Email address to validate
            
        Returns:
            Tuple[bool, str, Dict]: (is_valid, main_reason, detailed_results)
        """
        if not email or pd.isna(email):
            return False, "Empty email", {}
        
        email = str(email).strip()
        results = {
            'email': email,
            'format_valid': False,
            'domain_exists': False,
            'has_mx_record': False,
            'smtp_valid': False,
            'is_disposable': False,
            'is_role_based': False,
            'is_catch_all': False,
            'details': []
        }
        
        # 1. Format validation
        format_valid, format_detail = self.validate_email_format(email)
        results['format_valid'] = format_valid
        results['details'].append(f"Format: {format_detail}")
        
        if not format_valid:
            return False, format_detail, results
        
        domain = email.split('@')[1]
        
        # 2. Domain existence check
        domain_exists, domain_detail = self.check_domain_exists(domain)
        results['domain_exists'] = domain_exists
        results['details'].append(f"Domain: {domain_detail}")
        
        # 3. MX record validation
        has_mx, mx_record, mx_detail = self.get_mx_record(domain)
        results['has_mx_record'] = has_mx
        results['details'].append(f"MX: {mx_detail}")
        
        # 4. Disposable email check
        if self.check_disposable:
            is_disposable, disposable_detail = self.check_disposable_domain(domain)
            results['is_disposable'] = is_disposable
            results['details'].append(f"Disposable: {disposable_detail}")
            
            if is_disposable:
                return False, "Disposable email address", results
        
        # 5. Role-based email check
        if self.check_role_based:
            is_role_based, role_detail = self.check_role_based_email(email)
            results['is_role_based'] = is_role_based
            results['details'].append(f"Role-based: {role_detail}")
            
            # Note: We don't automatically reject role-based emails, just flag them
        
        # 6. SMTP validation (if enabled)
        if self.smtp_check and has_mx:
            smtp_valid, smtp_detail = self.smtp_validate(email)
            results['smtp_valid'] = smtp_valid
            results['details'].append(f"SMTP: {smtp_detail}")
            
            # 7. Catch-all domain check (only if SMTP is enabled)
            is_catch_all, catch_all_detail = self.check_catch_all_domain(domain)
            results['is_catch_all'] = is_catch_all
            results['details'].append(f"Catch-all: {catch_all_detail}")
            
            if not smtp_valid:
                return False, smtp_detail, results
            
            return True, "Valid (SMTP verified)", results
        
        # If SMTP check is disabled, base validity on format, domain, and MX
        if not domain_exists:
            return False, "Domain does not exist", results
        
        if not has_mx:
            return False, "No MX record found", results
        
        return True, "Valid (format and domain verified)", results
    
    def process_dataframe(self, df: pd.DataFrame, email_column: str, progress_callback=None) -> Dict:
        """
        Process DataFrame and validate emails with enhanced analysis
        
        Args:
            df (pd.DataFrame): DataFrame containing emails
            email_column (str): Name of the email column
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict: Enhanced results containing detailed validation information
        """
        if email_column not in df.columns:
            raise ValueError(f"Column '{email_column}' not found in file")
        
        valid_emails = []
        bounced_emails = []
        total_emails = len(df)
        
        # Enhanced counters
        stats = {
            'format_errors': 0,
            'domain_errors': 0,
            'mx_errors': 0,
            'smtp_errors': 0,
            'disposable_emails': 0,
            'role_based_emails': 0,
            'catch_all_domains': 0
        }
        
        for index, email in df[email_column].items():
            is_valid, reason, detailed_results = self.validate_email(email)
            
            # Update statistics
            if not detailed_results.get('format_valid', False):
                stats['format_errors'] += 1
            if not detailed_results.get('domain_exists', False):
                stats['domain_errors'] += 1
            if not detailed_results.get('has_mx_record', False):
                stats['mx_errors'] += 1
            if self.smtp_check and not detailed_results.get('smtp_valid', False):
                stats['smtp_errors'] += 1
            if detailed_results.get('is_disposable', False):
                stats['disposable_emails'] += 1
            if detailed_results.get('is_role_based', False):
                stats['role_based_emails'] += 1
            if detailed_results.get('is_catch_all', False):
                stats['catch_all_domains'] += 1
            
            email_info = {
                'email': str(email).strip() if email else '',
                'row': index + 1,
                'reason': reason,
                'format_valid': detailed_results.get('format_valid', False),
                'domain_exists': detailed_results.get('domain_exists', False),
                'has_mx_record': detailed_results.get('has_mx_record', False),
                'smtp_valid': detailed_results.get('smtp_valid', False) if self.smtp_check else None,
                'is_disposable': detailed_results.get('is_disposable', False),
                'is_role_based': detailed_results.get('is_role_based', False),
                'is_catch_all': detailed_results.get('is_catch_all', False),
                'details': '; '.join(detailed_results.get('details', []))
            }
            
            if is_valid:
                valid_emails.append(email_info)
            else:
                bounced_emails.append(email_info)
            
            # Update progress
            if progress_callback and (index + 1) % 5 == 0:
                progress = (index + 1) / total_emails
                progress_callback(progress, f"Processed {index + 1}/{total_emails} emails")
        
        return {
            'total': len(df),
            'valid': valid_emails,
            'bounced': bounced_emails,
            'valid_count': len(valid_emails),
            'bounced_count': len(bounced_emails),
            'statistics': stats,
            'validation_settings': {
                'smtp_check': self.smtp_check,
                'check_disposable': self.check_disposable,
                'check_role_based': self.check_role_based,
                'timeout': self.timeout
            }
        }


def detect_email_column(df: pd.DataFrame) -> str:
    """
    Auto-detect email column in DataFrame
    
    Args:
        df (pd.DataFrame): DataFrame to analyze
        
    Returns:
        str: Name of the email column or None if not found
    """
    # Look for columns with 'email' in the name
    email_columns = [col for col in df.columns if 'email' in col.lower()]
    if email_columns:
        return email_columns[0]
    
    # Look for columns that might contain emails
    for col in df.columns:
        sample_values = df[col].dropna().head(5)
        if not sample_values.empty:
            for value in sample_values:
                if isinstance(value, str) and '@' in value and '.' in value:
                    return col
    
    return None


def create_download_link(df: pd.DataFrame, filename: str, label: str):
    """
    Create a download link for DataFrame
    
    Args:
        df (pd.DataFrame): DataFrame to download
        filename (str): Name of the file
        label (str): Label for the download button
    """
    csv = df.to_csv(index=False)
    st.download_button(
        label=label,
        data=csv,
        file_name=filename,
        mime='text/csv'
    )


def main():
    st.set_page_config(
        page_title="Email Validator",
        page_icon="📧",
        layout="wide"
    )
    
    st.title("📧 Email Validator")
    st.markdown("Upload a CSV or Excel file to validate email addresses")
    
    # Sidebar for settings
    st.sidebar.header("⚙️ Validation Settings")
    
    # Basic settings
    smtp_check = st.sidebar.checkbox(
        "Enable SMTP Validation",
        help="Slower but more accurate validation by checking with mail servers"
    )
    
    timeout = st.sidebar.slider(
        "SMTP Timeout (seconds)",
        min_value=5,
        max_value=30,
        value=10,
        help="Timeout for SMTP connections"
    )
    
    # Advanced settings
    st.sidebar.subheader("🔍 Advanced Checks")
    
    check_disposable = st.sidebar.checkbox(
        "Check Disposable Domains",
        value=True,
        help="Detect and flag disposable/temporary email addresses"
    )
    
    check_role_based = st.sidebar.checkbox(
        "Check Role-based Emails",
        value=True,
        help="Detect role-based emails like admin@, support@, etc."
    )
    
    # Information about validation levels
    st.sidebar.subheader("📊 Validation Levels")
    st.sidebar.markdown("""
    **🟢 Basic**: Format + Domain + MX record
    
    **🔵 Enhanced**: + Disposable + Role-based detection
    
    **🔴 Complete**: + SMTP verification + Catch-all detection
    """)
    
    if smtp_check:
        st.sidebar.warning("⚠️ SMTP validation may be blocked by some servers and will be slower")
    
    # Show feature status
    st.sidebar.subheader("✅ Active Features")
    features = []
    features.append("✅ Syntax validation (RFC 5322)")
    features.append("✅ Domain existence check")
    features.append("✅ MX record validation")
    
    if smtp_check:
        features.append("✅ SMTP verification")
        features.append("✅ Catch-all detection")
    else:
        features.append("❌ SMTP verification")
        features.append("❌ Catch-all detection")
    
    if check_disposable:
        features.append("✅ Disposable email detection")
    else:
        features.append("❌ Disposable email detection")
    
    if check_role_based:
        features.append("✅ Role-based email detection")
    else:
        features.append("❌ Role-based email detection")
    
    for feature in features:
        st.sidebar.text(feature)
    
    # File upload
    st.header("📁 Upload File")
    uploaded_file = st.file_uploader(
        "Choose a CSV or Excel file",
        type=['csv', 'xlsx', 'xls'],
        help="Upload a file containing email addresses"
    )
    
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            
            st.success(f"✅ File uploaded successfully! Found {len(df)} rows.")
            
            # Show file preview
            st.subheader("📋 File Preview")
            st.dataframe(df.head(), use_container_width=True)
            
            # Column selection
            st.subheader("📬 Select Email Column")
            
            # Auto-detect email column
            detected_column = detect_email_column(df)
            
            if detected_column:
                st.info(f"🔍 Auto-detected email column: **{detected_column}**")
                default_index = list(df.columns).index(detected_column)
            else:
                st.warning("⚠️ Could not auto-detect email column. Please select manually.")
                default_index = 0
            
            email_column = st.selectbox(
                "Choose the column containing email addresses:",
                options=df.columns.tolist(),
                index=default_index
            )
            
            # Show sample emails from selected column
            sample_emails = df[email_column].dropna().head(5).tolist()
            if sample_emails:
                st.write("**Sample emails from selected column:**")
                for email in sample_emails:
                    st.write(f"• {email}")
            
            # Validation button
            if st.button("🚀 Validate Emails", type="primary"):
                # Create validator with enhanced settings
                validator = EmailValidator(
                    smtp_check=smtp_check, 
                    timeout=timeout,
                    check_disposable=check_disposable,
                    check_role_based=check_role_based
                )
                
                # Show validation info
                validation_level = "🟢 Basic"
                if check_disposable or check_role_based:
                    validation_level = "🔵 Enhanced"
                if smtp_check:
                    validation_level = "🔴 Complete"
                
                st.info(f"Starting {validation_level} email validation...")
                
                if smtp_check:
                    st.warning("⏳ SMTP validation enabled - this may take longer...")
                
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def update_progress(progress, message):
                    progress_bar.progress(progress)
                    status_text.text(message)
                
                # Start validation
                start_time = time.time()
                
                try:
                    results = validator.process_dataframe(
                        df, 
                        email_column, 
                        progress_callback=update_progress
                    )
                    
                    # Complete progress
                    progress_bar.progress(1.0)
                    status_text.text("✅ Validation completed!")
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    # Display results
                    st.header("📊 Enhanced Validation Results")
                    
                    # Summary metrics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Emails", results['total'])
                    
                    with col2:
                        st.metric("Valid Emails", results['valid_count'])
                    
                    with col3:
                        st.metric("Invalid Emails", results['bounced_count'])
                    
                    with col4:
                        valid_rate = (results['valid_count'] / results['total'] * 100) if results['total'] > 0 else 0
                        st.metric("Valid Rate", f"{valid_rate:.1f}%")
                    
                    st.info(f"⏱️ Validation completed in {duration:.2f} seconds")
                    
                    # Enhanced statistics
                    if 'statistics' in results:
                        st.subheader("📈 Detailed Statistics")
                        stats = results['statistics']
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Format Errors", stats['format_errors'])
                            st.metric("Domain Errors", stats['domain_errors'])
                        with col2:
                            st.metric("MX Record Errors", stats['mx_errors'])
                            if smtp_check:
                                st.metric("SMTP Errors", stats['smtp_errors'])
                        with col3:
                            if check_disposable:
                                st.metric("Disposable Emails", stats['disposable_emails'])
                            if check_role_based:
                                st.metric("Role-based Emails", stats['role_based_emails'])
                        with col4:
                            if smtp_check:
                                st.metric("Catch-all Domains", stats['catch_all_domains'])
                    
                    # Show detailed results
                    tab1, tab2, tab3, tab4 = st.tabs(["✅ Valid Emails", "❌ Invalid Emails", "� Detailed Analysis", "�📈 Summary"])
                    
                    with tab1:
                        if results['valid']:
                            valid_df = pd.DataFrame(results['valid'])
                            
                            # Show enhanced columns
                            display_cols = ['email', 'row', 'reason']
                            if check_disposable:
                                display_cols.append('is_disposable')
                            if check_role_based:
                                display_cols.append('is_role_based')
                            if smtp_check:
                                display_cols.extend(['smtp_valid', 'is_catch_all'])
                            
                            st.dataframe(valid_df[display_cols], use_container_width=True)
                            create_download_link(
                                valid_df,
                                "valid_emails_enhanced.csv",
                                "📥 Download Valid Emails (Enhanced)"
                            )
                        else:
                            st.info("No valid emails found.")
                    
                    with tab2:
                        if results['bounced']:
                            bounced_df = pd.DataFrame(results['bounced'])
                            
                            # Show enhanced columns for invalid emails
                            display_cols = ['email', 'row', 'reason', 'format_valid', 'domain_exists', 'has_mx_record']
                            if check_disposable:
                                display_cols.append('is_disposable')
                            if check_role_based:
                                display_cols.append('is_role_based')
                            
                            st.dataframe(bounced_df[display_cols], use_container_width=True)
                            create_download_link(
                                bounced_df,
                                "invalid_emails_enhanced.csv",
                                "📥 Download Invalid Emails (Enhanced)"
                            )
                        else:
                            st.info("No invalid emails found.")
                    
                    with tab3:
                        st.subheader("🔍 Detailed Validation Analysis")
                        
                        # Combine all results for detailed analysis
                        all_emails = results['valid'] + results['bounced']
                        if all_emails:
                            analysis_df = pd.DataFrame(all_emails)
                            
                            # Show full details
                            st.dataframe(analysis_df, use_container_width=True)
                            
                            # Validation breakdown
                            st.subheader("📊 Validation Breakdown")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write("**Format Validation:**")
                                format_valid = analysis_df['format_valid'].sum()
                                st.write(f"✅ Valid format: {format_valid}/{len(analysis_df)}")
                                
                                st.write("**Domain Validation:**")
                                domain_valid = analysis_df['domain_exists'].sum()
                                st.write(f"✅ Domain exists: {domain_valid}/{len(analysis_df)}")
                                
                                st.write("**MX Record Validation:**")
                                mx_valid = analysis_df['has_mx_record'].sum()
                                st.write(f"✅ Has MX record: {mx_valid}/{len(analysis_df)}")
                            
                            with col2:
                                if check_disposable:
                                    st.write("**Disposable Email Detection:**")
                                    disposable_count = analysis_df['is_disposable'].sum()
                                    st.write(f"⚠️ Disposable emails: {disposable_count}/{len(analysis_df)}")
                                
                                if check_role_based:
                                    st.write("**Role-based Email Detection:**")
                                    role_count = analysis_df['is_role_based'].sum()
                                    st.write(f"ℹ️ Role-based emails: {role_count}/{len(analysis_df)}")
                                
                                if smtp_check:
                                    st.write("**SMTP Validation:**")
                                    smtp_valid = analysis_df['smtp_valid'].sum() if 'smtp_valid' in analysis_df.columns else 0
                                    st.write(f"✅ SMTP verified: {smtp_valid}/{len(analysis_df)}")
                    
                    with tab4:
                        summary_data = {
                            'Metric': ['Total Emails', 'Valid Emails', 'Invalid Emails', 'Valid Rate (%)', 'Format Errors', 'Domain Errors', 'MX Errors'],
                            'Value': [
                                results['total'],
                                results['valid_count'],
                                results['bounced_count'],
                                round(valid_rate, 2),
                                stats.get('format_errors', 0),
                                stats.get('domain_errors', 0),
                                stats.get('mx_errors', 0)
                            ]
                        }
                        
                        if smtp_check:
                            summary_data['Metric'].extend(['SMTP Errors', 'Catch-all Domains'])
                            summary_data['Value'].extend([stats.get('smtp_errors', 0), stats.get('catch_all_domains', 0)])
                        
                        if check_disposable:
                            summary_data['Metric'].append('Disposable Emails')
                            summary_data['Value'].append(stats.get('disposable_emails', 0))
                        
                        if check_role_based:
                            summary_data['Metric'].append('Role-based Emails')
                            summary_data['Value'].append(stats.get('role_based_emails', 0))
                        
                        summary_df = pd.DataFrame(summary_data)
                        st.dataframe(summary_df, use_container_width=True)
                        create_download_link(
                            summary_df,
                            "validation_summary_enhanced.csv",
                            "📥 Download Enhanced Summary"
                        )
                        
                        # Enhanced Visualization
                        st.subheader("📊 Enhanced Validation Chart")
                        
                        # Main validation result chart
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            chart_data = pd.DataFrame({
                                'Status': ['Valid', 'Invalid'],
                                'Count': [results['valid_count'], results['bounced_count']]
                            })
                            st.bar_chart(chart_data.set_index('Status'))
                        
                        with col2:
                            # Error breakdown chart
                            if stats:
                                error_data = pd.DataFrame({
                                    'Error Type': ['Format', 'Domain', 'MX Record'],
                                    'Count': [stats['format_errors'], stats['domain_errors'], stats['mx_errors']]
                                })
                                if smtp_check:
                                    error_data = pd.concat([error_data, pd.DataFrame({
                                        'Error Type': ['SMTP'],
                                        'Count': [stats['smtp_errors']]
                                    })], ignore_index=True)
                                
                                st.bar_chart(error_data.set_index('Error Type'))
                
                except Exception as e:
                    st.error(f"❌ Error during validation: {str(e)}")
                    import traceback
                    st.error(f"Details: {traceback.format_exc()}")
                    
        except Exception as e:
            st.error(f"❌ Error reading file: {str(e)}")
    
    else:
        # Show instructions when no file is uploaded
        st.info("👆 Please upload a CSV or Excel file to get started")
        
        st.subheader("📝 Instructions")
        st.markdown("""
        1. **Upload your file**: Choose a CSV or Excel file containing email addresses
        2. **Select email column**: The app will try to auto-detect the email column
        3. **Configure settings**: Optionally enable SMTP validation for more accurate results
        4. **Validate**: Click the validate button to process your emails
        5. **Download results**: Get separate files for valid emails, bounced emails, and summary
        
        **Supported file formats**: CSV, XLSX, XLS
        
        **Validation methods**:
        - **Format validation**: Checks if email follows proper format (fast)
        - **SMTP validation**: Contacts mail servers to verify email exists (slower but more accurate)
        """)


if __name__ == "__main__":
    main()
