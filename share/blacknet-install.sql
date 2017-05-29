--
-- Database: `blacknet`
--

-- --------------------------------------------------------
--
-- Table structure for table `locations`
--
CREATE TABLE IF NOT EXISTS `locations` (
  `locId` int(10) unsigned NOT NULL,
  `country` char(2) NOT NULL,
  `region` char(2) DEFAULT NULL,
  `city` varchar(64) DEFAULT NULL,
  `postalCode` varchar(64) DEFAULT NULL,
  `latitude` float NOT NULL,
  `longitude` float NOT NULL,
  `metroCode` int(10) unsigned DEFAULT NULL,
  `areaCode` int(11) DEFAULT NULL,
  PRIMARY KEY (`locId`),
  INDEX (`country`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `blocks`
--
CREATE TABLE IF NOT EXISTS `blocks` (
  `startIpNum` int(10) unsigned NOT NULL,
  `endIpNum` int(10) unsigned NOT NULL,
  `locId` int(10) unsigned NOT NULL,
  KEY `startIpNum` (`startIpNum`),
  KEY `endIpNum` (`endIpNum`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `countries`
--
CREATE TABLE IF NOT EXISTS `countries` (
  `code` char(2) NOT NULL,
  `country` varchar(50) NOT NULL,
  PRIMARY KEY (`code`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


INSERT INTO `countries` VALUES ('BD','Bangladesh'),('BE','Belgium'),('BF','Burkina Faso'),('BG','Bulgaria'),('BA','Bosnia and Herzegovina'),('BB','Barbados'),('WF','Wallis and Futuna'),('BL','Saint Barthélemy'),('BM','Bermuda'),('BN','Brunei Darussalam'),('BO','Bolivia'),('BH','Bahrain'),('BI','Burundi'),('BJ','Benin'),('BT','Bhutan'),('JM','Jamaica'),('BV','Bouvet Island'),('BW','Botswana'),('WS','Samoa'),('BQ','Caribbean Netherlands '),('BR','Brazil'),('BS','Bahamas'),('JE','Jersey'),('BY','Belarus'),('O1','Other Country'),('LV','Latvia'),('RW','Rwanda'),('RS','Serbia'),('TL','Timor-Leste'),('RE','Reunion'),('LU','Luxembourg'),('TJ','Tajikistan'),('RO','Romania'),('PG','Papua New Guinea'),('GW','Guinea-Bissau'),('GU','Guam'),('GT','Guatemala'),('GS','South Georgia and the South Sandwich Islands'),('GR','Greece'),('GQ','Equatorial Guinea'),('GP','Guadeloupe'),('JP','Japan'),('GY','Guyana'),('GG','Guernsey'),('GF','French Guiana'),('GE','Georgia'),('GD','Grenada'),('GB','United Kingdom'),('GA','Gabon'),('SV','El Salvador'),('GN','Guinea'),('GM','Gambia'),('GL','Greenland'),('GI','Gibraltar'),('GH','Ghana'),('OM','Oman'),('TN','Tunisia'),('JO','Jordan'),('HR','Croatia'),('HT','Haiti'),('HU','Hungary'),('HK','Hong Kong'),('HN','Honduras'),('HM','Heard Island and McDonald Islands'),('VE','Venezuela'),('PR','Puerto Rico'),('PS','Palestinian Territory'),('PW','Palau'),('PT','Portugal'),('SJ','Svalbard and Jan Mayen'),('PY','Paraguay'),('IQ','Iraq'),('PA','Panama'),('PF','French Polynesia'),('BZ','Belize'),('PE','Peru'),('PK','Pakistan'),('PH','Philippines'),('PN','Pitcairn'),('TM','Turkmenistan'),('PL','Poland'),('PM','Saint Pierre and Miquelon'),('ZM','Zambia'),('EH','Western Sahara'),('RU','Russian Federation'),('EE','Estonia'),('EG','Egypt'),('TK','Tokelau'),('ZA','South Africa'),('EC','Ecuador'),('IT','Italy'),('VN','Vietnam'),('SB','Solomon Islands'),('EU','Europe'),('ET','Ethiopia'),('SO','Somalia'),('ZW','Zimbabwe'),('SA','Saudi Arabia'),('ES','Spain'),('ER','Eritrea'),('ME','Montenegro'),('MD','Moldova, Republic of'),('MG','Madagascar'),('MF','Saint-Martin (France)'),('MA','Morocco'),('MC','Monaco'),('UZ','Uzbekistan'),('MM','Myanmar'),('ML','Mali'),('MO','Macao'),('MN','Mongolia'),('MH','Marshall Islands'),('MK','Macedonia'),('MU','Mauritius'),('MT','Malta'),('MW','Malawi'),('MV','Maldives'),('MQ','Martinique'),('MP','Northern Mariana Islands'),('MS','Montserrat'),('MR','Mauritania'),('IM','Isle of Man'),('UG','Uganda'),('TZ','Tanzania, United Republic of'),('MY','Malaysia'),('MX','Mexico'),('IL','Israel'),('FR','France'),('IO','British Indian Ocean Territory'),('SH','Saint Helena'),('FI','Finland'),('FJ','Fiji'),('FK','Falkland Islands (Malvinas)'),('FM','Micronesia, Federated States of'),('FO','Faroe Islands'),('NI','Nicaragua'),('NL','Netherlands'),('NO','Norway'),('NA','Namibia'),('VU','Vanuatu'),('NC','New Caledonia'),('NE','Niger'),('NF','Norfolk Island'),('NG','Nigeria'),('NZ','New Zealand'),('NP','Nepal'),('NR','Nauru'),('NU','Niue'),('CK','Cook Islands'),('CI',"Cote d\'Ivoire"),('CH','Switzerland'),('CO','Colombia'),('CN','China'),('CM','Cameroon'),('CL','Chile'),('CC','Cocos (Keeling) Islands'),('CA','Canada'),('CG','Congo'),('CF','Central African Republic'),('CD','Congo, The Democratic Republic of the'),('CZ','Czech Republic'),('CY','Cyprus'),('CX','Christmas Island'),('CR','Costa Rica'),('CW','Curaçao'),('CV','Cape Verde'),('CU','Cuba'),('SZ','Swaziland'),('SY','Syrian Arab Republic'),('SX','Sint Maarten (Dutch part)'),('KG','Kyrgyzstan'),('KE','Kenya'),('SS','South Sudan'),('SR','Suriname'),('KI','Kiribati'),('KH','Cambodia'),('KN','Saint Kitts and Nevis'),('KM','Comoros'),('ST','Sao Tome and Principe'),('SK','Slovakia'),('KR','Korea, Republic of'),('SI','Slovenia'),('KP','Korea, Democratic People's Republic of'),('KW','Kuwait'),('SN','Senegal'),('SM','San Marino'),('SL','Sierra Leone'),('SC','Seychelles'),('KZ','Kazakhstan'),('KY','Cayman Islands'),('SG','Singapore'),('SE','Sweden'),('SD','Sudan'),('DO','Dominican Republic'),('DM','Dominica'),('DJ','Djibouti'),('DK','Denmark'),('VG','Virgin Islands, British'),('DE','Germany'),('YE','Yemen'),('DZ','Algeria'),('US','United States'),('UY','Uruguay'),('YT','Mayotte'),('UM','United States Minor Outlying Islands'),('LB','Lebanon'),('LC','Saint Lucia'),('LA','Lao People's Democratic Republic'),('TV','Tuvalu'),('TW','Taiwan'),('TT','Trinidad and Tobago'),('TR','Turkey'),('LK','Sri Lanka'),('LI','Liechtenstein'),('A1','Anonymous Proxy'),('TO','Tonga'),('LT','Lithuania'),('A2','Satellite Provider'),('LR','Liberia'),('LS','Lesotho'),('TH','Thailand'),('TF','French Southern Territories'),('TG','Togo'),('TD','Chad'),('TC','Turks and Caicos Islands'),('LY','Libyan Arab Jamahiriya'),('VA','Holy See (Vatican City State)'),('VC','Saint Vincent and the Grenadines'),('AE','United Arab Emirates'),('AD','Andorra'),('AG','Antigua and Barbuda'),('AF','Afghanistan'),('AI','Anguilla'),('VI','Virgin Islands, U.S.'),('IS','Iceland'),('IR','Iran, Islamic Republic of'),('AM','Armenia'),('AL','Albania'),('AO','Angola'),('AN','Netherlands Antilles'),('AQ','Antarctica'),('AP','Asia/Pacific Region'),('AS','American Samoa'),('AR','Argentina'),('AU','Australia'),('AT','Austria'),('AW','Aruba'),('IN','India'),('AX','Aland Islands'),('AZ','Azerbaijan'),('IE','Ireland'),('ID','Indonesia'),('UA','Ukraine'),('QA','Qatar'),('MZ','Mozambique');


-- --------------------------------------------------------
--
-- Table structure for table `attackers`
--
CREATE TABLE IF NOT EXISTS `attackers` (
  `id` int(10) unsigned,
  `ip` varchar(15) NOT NULL,
  `first_seen` DATETIME,
  `last_seen` DATETIME,
  `dns` varchar(256) NOT NULL,
  `notes` TEXT DEFAULT "" NOT NULL,
  `locId` int(10) unsigned NOT NULL,
  `n_attempts` int(10) unsigned DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX (`last_seen`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `attempts`
--
CREATE TABLE IF NOT EXISTS `attempts` (
  `id` int(10) unsigned AUTO_INCREMENT,
  `attacker_id` int(10) unsigned NOT NULL,
  `session_id` int(10) unsigned NOT NULL,
  `user` varchar(64) NOT NULL,
  `password` varchar(64),
  `target` varchar(15) NOT NULL,
  `date` DATETIME,
  `client` varchar(128) DEFAULT "" NOT NULL,
  `success` boolean DEFAULT false,
  PRIMARY KEY (`id`),
  INDEX (`session_id`),
  INDEX (`attacker_id`),
  INDEX (`date`),
  INDEX (`target`),
  INDEX (`user`),
  INDEX (`password`),
  INDEX (`user`, `password`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `pubkeys`
--
CREATE TABLE IF NOT EXISTS `pubkeys` (
  `id` INT(10) UNSIGNED AUTO_INCREMENT,
  `name` VARCHAR(16) NOT NULL,
  `fingerprint` CHAR(32) NOT NULL,
  `data` TEXT NOT NULL,
  `bits` INT(5) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE (`fingerprint`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `attempts_pubkeys`
--
CREATE TABLE IF NOT EXISTS `attempts_pubkeys` (
  `attempt_id` INT(10) UNSIGNED NOT NULL,
  `pubkey_id` INT(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`attempt_id`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `sessions`
--
CREATE TABLE IF NOT EXISTS `sessions` (
  `id` int(10) unsigned AUTO_INCREMENT,
  `attacker_id` int(10) unsigned NOT NULL,
  `first_attempt` DATETIME,
  `last_attempt` DATETIME,
  `target` varchar(15) NOT NULL,
  `n_attempts` int(10) unsigned DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX (`attacker_id`),
  INDEX (`last_attempt`),
  INDEX (`target`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `events`
--
CREATE TABLE IF NOT EXISTS `events` (
  `id` int(10) unsigned AUTO_INCREMENT,
  `date` DATETIME,
  `target` varchar(15) NOT NULL,
  `type` varchar(15) NOT NULL,
  `content` varchar(255) DEFAULT "" NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


-- --------------------------------------------------------
--
-- Table structure for table `commands`
--
CREATE TABLE IF NOT EXISTS `commands` (
  `id` int(10) unsigned AUTO_INCREMENT,
  `attacker_id` int(10) unsigned NOT NULL,
  `date` DATETIME,
  `target` varchar(15) NOT NULL,
  `login` varchar(15) NOT NULL,
  `command` text DEFAULT "" NOT NULL,
  PRIMARY KEY (`id`),
  INDEX (`attacker_id`)
) ENGINE=MyISAM DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


delimiter |


-- --------------------------------------------------------
--
-- Trigger `add_attempt` for redundancy (and performances)
--
CREATE TRIGGER `add_attempt`
AFTER INSERT ON `attempts`
FOR EACH ROW
BEGIN
  UPDATE attackers SET n_attempts = n_attempts + 1 WHERE id = NEW.attacker_id;
  UPDATE sessions  SET n_attempts = n_attempts + 1 WHERE id = NEW.session_id;
END;
|


-- --------------------------------------------------------
--
-- Trigger `rm_attempt`
--
CREATE TRIGGER `rm_attempt`
AFTER DELETE ON `attempts`
FOR EACH ROW
BEGIN
  UPDATE attackers SET n_attempts = n_attempts - 1 WHERE id = OLD.attacker_id;
  UPDATE sessions  SET n_attempts = n_attempts - 1 WHERE id = OLD.session_id;
END;
|


delimiter ;
