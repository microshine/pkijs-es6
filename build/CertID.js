"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CertID = function () {
	//**********************************************************************************
	/**
  * Constructor for CertID class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertID() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertID);

		//region Internal properties of the object
		/**
   * @type {AlgorithmIdentifier}
   * @description hashAlgorithm
   */
		this.hashAlgorithm = (0, _pvutils.getParametersValue)(parameters, "hashAlgorithm", CertID.defaultValues("hashAlgorithm"));
		/**
   * @type {OctetString}
   * @description issuerNameHash
   */
		this.issuerNameHash = (0, _pvutils.getParametersValue)(parameters, "issuerNameHash", CertID.defaultValues("issuerNameHash"));
		/**
   * @type {OctetString}
   * @description issuerKeyHash
   */
		this.issuerKeyHash = (0, _pvutils.getParametersValue)(parameters, "issuerKeyHash", CertID.defaultValues("issuerKeyHash"));
		/**
   * @type {Integer}
   * @description serialNumber
   */
		this.serialNumber = (0, _pvutils.getParametersValue)(parameters, "serialNumber", CertID.defaultValues("serialNumber"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(CertID, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertID.schema({
				names: {
					hashAlgorithm: "hashAlgorithm",
					issuerNameHash: "issuerNameHash",
					issuerKeyHash: "issuerKeyHash",
					serialNumber: "serialNumber"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CertID");
			//endregion

			//region Get internal properties from parsed schema
			this.hashAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.hashAlgorithm });
			this.issuerNameHash = asn1.result.issuerNameHash;
			this.issuerKeyHash = asn1.result.issuerKeyHash;
			this.serialNumber = asn1.result.serialNumber;
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: [this.hashAlgorithm.toSchema(), this.issuerNameHash, this.issuerKeyHash, this.serialNumber]
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			return {
				hashAlgorithm: this.hashAlgorithm.toJSON(),
				issuerNameHash: this.issuerNameHash.toJSON(),
				issuerKeyHash: this.issuerKeyHash.toJSON(),
				serialNumber: this.serialNumber.toJSON()
			};
		}
		//**********************************************************************************
		/**
   * Check that two "CertIDs" are equal
   * @param {CertID} certificateID Identifier of the certificate to be checked
   * @returns {boolean}
   */

	}, {
		key: "isEqual",
		value: function isEqual(certificateID) {
			//region Check "hashAlgorithm"
			if (!this.hashAlgorithm.algorithmId === certificateID.hashAlgorithm.algorithmId) return false;
			//endregion

			//region Check "issuerNameHash"
			if ((0, _pvutils.isEqualBuffer)(this.issuerNameHash.valueBlock.valueHex, certificateID.issuerNameHash.valueBlock.valueHex) === false) return false;
			//endregion

			//region Check "issuerKeyHash"
			if ((0, _pvutils.isEqualBuffer)(this.issuerKeyHash.valueBlock.valueHex, certificateID.issuerKeyHash.valueBlock.valueHex) === false) return false;
			//endregion

			//region Check "serialNumber"
			if (!this.serialNumber.isEqual(certificateID.serialNumber)) return false;
			//endregion

			return true;
		}
		//**********************************************************************************
		/**
   * Making OCSP certificate identifier for specific certificate
   * @param {Certificate} certificate Certificate making OCSP Request for
   * @param {Object} parameters Additional parameters
   * @returns {Promise}
   */

	}, {
		key: "createForCertificate",
		value: function createForCertificate(certificate, parameters) {
			var _this = this;

			//region Initial variables
			var sequence = Promise.resolve();

			var issuerCertificate = void 0;
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Check input parameters
			if ("hashAlgorithm" in parameters === false) return Promise.reject("Parameter \"hashAlgorithm\" is mandatory for \"OCSP_REQUEST.createForCertificate\"");

			var hashOID = (0, _common.getOIDByAlgorithm)({ name: parameters.hashAlgorithm });
			if (hashOID === "") return Promise.reject("Incorrect \"hashAlgorithm\": " + this.hashAlgorithm);

			this.hashAlgorithm = new _AlgorithmIdentifier2.default({
				algorithmId: hashOID,
				algorithmParams: new asn1js.Null()
			});

			if ("issuerCertificate" in parameters) issuerCertificate = parameters.issuerCertificate;else return Promise.reject("Parameter \"issuerCertificate\" is mandatory for \"OCSP_REQUEST.createForCertificate\"");
			//endregion

			//region Initialize "serialNumber" field
			this.serialNumber = certificate.serialNumber;
			//endregion

			//region Create "issuerNameHash"
			sequence = sequence.then(function () {
				return crypto.digest({ name: parameters.hashAlgorithm }, issuerCertificate.subject.toSchema().toBER(false));
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			//region Create "issuerKeyHash"
			sequence = sequence.then(function (result) {
				_this.issuerNameHash = new asn1js.OctetString({ valueHex: result });

				var issuerKeyBuffer = issuerCertificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;

				return crypto.digest({ name: parameters.hashAlgorithm }, issuerKeyBuffer);
			}, function (error) {
				return Promise.reject(error);
			}).then(function (result) {
				_this.issuerKeyHash = new asn1js.OctetString({ valueHex: result });
			}, function (error) {
				return Promise.reject(error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "hashAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "issuerNameHash":
				case "issuerKeyHash":
					return new asn1js.OctetString();
				case "serialNumber":
					return new asn1js.Integer();
				default:
					throw new Error("Invalid member name for CertID class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "hashAlgorithm":
					return memberValue.algorithmId === "" && "algorithmParams" in memberValue === false;
				case "issuerNameHash":
				case "issuerKeyHash":
				case "serialNumber":
					return memberValue.isEqual(CertID.defaultValues(memberName));
				default:
					throw new Error("Invalid member name for CertID class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//CertID          ::=     SEQUENCE {
			//    hashAlgorithm       AlgorithmIdentifier,
			//    issuerNameHash      OCTET STRING, -- Hash of issuer's DN
			//    issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
			//    serialNumber        CertificateSerialNumber }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [hashAlgorithm]
    * @property {string} [hashAlgorithmObject]
    * @property {string} [issuerNameHash]
    * @property {string} [issuerKeyHash]
    * @property {string} [serialNumber]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [_AlgorithmIdentifier2.default.schema(names.hashAlgorithmObject || {
					names: {
						blockName: names.hashAlgorithm || ""
					}
				}), new asn1js.OctetString({ name: names.issuerNameHash || "" }), new asn1js.OctetString({ name: names.issuerKeyHash || "" }), new asn1js.Integer({ name: names.serialNumber || "" })]
			});
		}
	}]);

	return CertID;
}();
//**************************************************************************************


exports.default = CertID;
//# sourceMappingURL=CertID.js.map