"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _SignedAndUnsignedAttributes = require("./SignedAndUnsignedAttributes");

var _SignedAndUnsignedAttributes2 = _interopRequireDefault(_SignedAndUnsignedAttributes);

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var SignerInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for SignerInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function SignerInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, SignerInfo);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", SignerInfo.defaultValues("version"));
		/**
   * @type {Object}
   * @description sid
   */
		this.sid = (0, _pvutils.getParametersValue)(parameters, "sid", SignerInfo.defaultValues("sid"));
		/**
   * @type {AlgorithmIdentifier}
   * @description digestAlgorithm
   */
		this.digestAlgorithm = (0, _pvutils.getParametersValue)(parameters, "digestAlgorithm", SignerInfo.defaultValues("digestAlgorithm"));

		if ("signedAttrs" in parameters)
			/**
    * @type {SignedAndUnsignedAttributes}
    * @description signedAttrs
    */
			this.signedAttrs = (0, _pvutils.getParametersValue)(parameters, "signedAttrs", SignerInfo.defaultValues("signedAttrs"));

		/**
   * @type {AlgorithmIdentifier}
   * @description digestAlgorithm
   */
		this.signatureAlgorithm = (0, _pvutils.getParametersValue)(parameters, "signatureAlgorithm", SignerInfo.defaultValues("signatureAlgorithm"));
		/**
   * @type {OctetString}
   * @description signature
   */
		this.signature = (0, _pvutils.getParametersValue)(parameters, "signature", SignerInfo.defaultValues("signature"));

		if ("unsignedAttrs" in parameters)
			/**
    * @type {SignedAndUnsignedAttributes}
    * @description unsignedAttrs
    */
			this.unsignedAttrs = (0, _pvutils.getParametersValue)(parameters, "unsignedAttrs", SignerInfo.defaultValues("unsignedAttrs"));
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


	_createClass(SignerInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, SignerInfo.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_SIGNER_INFO");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result["SignerInfo.version"].valueBlock.valueDec;

			var currentSid = asn1.result["SignerInfo.sid"];
			if (currentSid.idBlock.tagClass === 1) this.sid = new _IssuerAndSerialNumber2.default({ schema: currentSid });else this.sid = currentSid;

			this.digestAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result["SignerInfo.digestAlgorithm"] });
			if ("SignerInfo.signedAttrs" in asn1.result) this.signedAttrs = new _SignedAndUnsignedAttributes2.default({ type: 0, schema: asn1.result["SignerInfo.signedAttrs"] });

			this.signatureAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result["SignerInfo.signatureAlgorithm"] });
			this.signature = asn1.result["SignerInfo.signature"];
			if ("SignerInfo.unsignedAttrs" in asn1.result) this.unsignedAttrs = new _SignedAndUnsignedAttributes2.default({ type: 1, schema: asn1.result["SignerInfo.unsignedAttrs"] });
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
			if (SignerInfo.compareWithDefault("sid", this.sid)) throw new Error("Incorrectly initialized \"SignerInfo\" class");

			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(new asn1js.Integer({ value: this.version }));

			if (this.sid instanceof _IssuerAndSerialNumber2.default) outputArray.push(this.sid.toSchema());else outputArray.push(this.sid);

			outputArray.push(this.digestAlgorithm.toSchema());

			if ("signedAttrs" in this) {
				if (SignerInfo.compareWithDefault("signedAttrs", this.signedAttrs) === false) outputArray.push(this.signedAttrs.toSchema());
			}

			outputArray.push(this.signatureAlgorithm.toSchema());
			outputArray.push(this.signature);

			if ("unsignedAttrs" in this) {
				if (SignerInfo.compareWithDefault("unsignedAttrs", this.unsignedAttrs) === false) outputArray.push(this.unsignedAttrs.toSchema());
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
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
			if (SignerInfo.compareWithDefault("sid", this.sid)) throw new Error("Incorrectly initialized \"SignerInfo\" class");

			var _object = {
				version: this.version
			};

			if (!(this.sid instanceof asn1js.Any)) _object.sid = this.sid.toJSON();

			_object.digestAlgorithm = this.digestAlgorithm.toJSON();

			if (SignerInfo.compareWithDefault("signedAttrs", this.signedAttrs) === false) _object.signedAttrs = this.signedAttrs.toJSON();

			_object.signatureAlgorithm = this.signatureAlgorithm.toJSON();
			_object.signature = this.signature.toJSON();

			if (SignerInfo.compareWithDefault("unsignedAttrs", this.unsignedAttrs) === false) _object.unsignedAttrs = this.unsignedAttrs.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 0;
				case "sid":
					return new asn1js.Any();
				case "digestAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signedAttrs":
					return new _SignedAndUnsignedAttributes2.default({ type: 0 });
				case "signatureAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "signature":
					return new asn1js.OctetString();
				case "unsignedAttrs":
					return new _SignedAndUnsignedAttributes2.default({ type: 1 });
				default:
					throw new Error("Invalid member name for SignerInfo class: " + memberName);
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
				case "version":
					return SignerInfo.defaultValues("version") === memberValue;
				case "sid":
					return memberValue instanceof asn1js.Any;
				case "digestAlgorithm":
					if (memberValue instanceof _AlgorithmIdentifier2.default === false) return false;

					return memberValue.isEqual(SignerInfo.defaultValues("digestAlgorithm"));
				case "signedAttrs":
					return _SignedAndUnsignedAttributes2.default.compareWithDefault("type", memberValue.type) && _SignedAndUnsignedAttributes2.default.compareWithDefault("attributes", memberValue.attributes) && _SignedAndUnsignedAttributes2.default.compareWithDefault("encodedValue", memberValue.encodedValue);
				case "signatureAlgorithm":
					if (memberValue instanceof _AlgorithmIdentifier2.default === false) return false;

					return memberValue.isEqual(SignerInfo.defaultValues("signatureAlgorithm"));
				case "signature":
				case "unsignedAttrs":
					return _SignedAndUnsignedAttributes2.default.compareWithDefault("type", memberValue.type) && _SignedAndUnsignedAttributes2.default.compareWithDefault("attributes", memberValue.attributes) && _SignedAndUnsignedAttributes2.default.compareWithDefault("encodedValue", memberValue.encodedValue);
				default:
					throw new Error("Invalid member name for SignerInfo class: " + memberName);
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

			//SignerInfo ::= SEQUENCE {
			//    version CMSVersion,
			//    sid SignerIdentifier,
			//    digestAlgorithm DigestAlgorithmIdentifier,
			//    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
			//    signatureAlgorithm SignatureAlgorithmIdentifier,
			//    signature SignatureValue,
			//    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
			//
			//SignerIdentifier ::= CHOICE {
			//    issuerAndSerialNumber IssuerAndSerialNumber,
			//    subjectKeyIdentifier [0] SubjectKeyIdentifier }
			//
			//SubjectKeyIdentifier ::= OCTET STRING

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [sid]
    * @property {string} [digestAlgorithm]
    * @property {string} [signedAttrs]
    * @property {string} [signatureAlgorithm]
    * @property {string} [signature]
    * @property {string} [unsignedAttrs]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: "SignerInfo",
				value: [new asn1js.Integer({ name: names.version || "SignerInfo.version" }), new asn1js.Choice({
					value: [_IssuerAndSerialNumber2.default.schema(names.sid || {
						names: {
							blockName: "SignerInfo.sid"
						}
					}), new asn1js.Constructed({
						optional: true,
						name: names.sid || "SignerInfo.sid",
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [new asn1js.OctetString()]
					})]
				}), _AlgorithmIdentifier2.default.schema(names.digestAlgorithm || {
					names: {
						blockName: "SignerInfo.digestAlgorithm"
					}
				}), _SignedAndUnsignedAttributes2.default.schema(names.signedAttrs || {
					names: {
						blockName: "SignerInfo.signedAttrs",
						tagNumber: 0
					}
				}), _AlgorithmIdentifier2.default.schema(names.signatureAlgorithm || {
					names: {
						blockName: "SignerInfo.signatureAlgorithm"
					}
				}), new asn1js.OctetString({ name: names.signature || "SignerInfo.signature" }), _SignedAndUnsignedAttributes2.default.schema(names.unsignedAttrs || {
					names: {
						blockName: "SignerInfo.unsignedAttrs",
						tagNumber: 1
					}
				})]
			});
		}
	}]);

	return SignerInfo;
}();
//**************************************************************************************


exports.default = SignerInfo;
//# sourceMappingURL=SignerInfo.js.map