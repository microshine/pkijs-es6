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

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

var _RecipientIdentifier = require("./RecipientIdentifier");

var _RecipientIdentifier2 = _interopRequireDefault(_RecipientIdentifier);

var _IssuerAndSerialNumber = require("./IssuerAndSerialNumber");

var _IssuerAndSerialNumber2 = _interopRequireDefault(_IssuerAndSerialNumber);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var KeyTransRecipientInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for KeyTransRecipientInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function KeyTransRecipientInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, KeyTransRecipientInfo);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", KeyTransRecipientInfo.defaultValues("version"));
		/**
   * @type {RecipientIdentifier}
   * @description rid
   */
		this.rid = (0, _pvutils.getParametersValue)(parameters, "rid", KeyTransRecipientInfo.defaultValues("rid"));
		/**
   * @type {AlgorithmIdentifier}
   * @description keyEncryptionAlgorithm
   */
		this.keyEncryptionAlgorithm = (0, _pvutils.getParametersValue)(parameters, "keyEncryptionAlgorithm", KeyTransRecipientInfo.defaultValues("keyEncryptionAlgorithm"));
		/**
   * @type {OctetString}
   * @description encryptedKey
   */
		this.encryptedKey = (0, _pvutils.getParametersValue)(parameters, "encryptedKey", KeyTransRecipientInfo.defaultValues("encryptedKey"));
		/**
   * @type {Certificate}
   * @description recipientCertificate For some reasons we need to store recipient's certificate here
   */
		this.recipientCertificate = (0, _pvutils.getParametersValue)(parameters, "recipientCertificate", KeyTransRecipientInfo.defaultValues("recipientCertificate"));
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


	_createClass(KeyTransRecipientInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, KeyTransRecipientInfo.schema({
				names: {
					version: "version",
					rid: {
						names: {
							blockName: "rid"
						}
					},
					keyEncryptionAlgorithm: {
						names: {
							blockName: "keyEncryptionAlgorithm"
						}
					},
					encryptedKey: "encryptedKey"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for KeyTransRecipientInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;

			if (asn1.result.rid.idBlock.tagClass === 3) this.rid = asn1.result.rid.valueBlock.value[0]; // SubjectKeyIdentifier
			else this.rid = new _IssuerAndSerialNumber2.default({ schema: asn1.result.rid });

			this.keyEncryptionAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.keyEncryptionAlgorithm });
			this.encryptedKey = asn1.result.encryptedKey;
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
			//region Create array for output sequence
			var outputArray = [];

			if (this.rid instanceof _IssuerAndSerialNumber2.default) {
				this.version = 0;

				outputArray.push(new asn1js.Integer({ value: this.version }));
				outputArray.push(this.rid.toSchema());
			} else {
				this.version = 2;

				outputArray.push(new asn1js.Integer({ value: this.version }));
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.rid]
				}));
			}

			outputArray.push(this.keyEncryptionAlgorithm.toSchema());
			outputArray.push(this.encryptedKey);
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
			return {
				version: this.version,
				rid: this.rid.toJSON(),
				keyEncryptionAlgorithm: this.keyEncryptionAlgorithm.toJSON(),
				encryptedKey: this.encryptedKey.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return -1;
				case "rid":
					return {};
				case "keyEncryptionAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "encryptedKey":
					return new asn1js.OctetString();
				case "recipientCertificate":
					return new _Certificate2.default();
				default:
					throw new Error("Invalid member name for KeyTransRecipientInfo class: " + memberName);
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
					return memberValue === KeyTransRecipientInfo.defaultValues("version");
				case "rid":
					return Object.keys(memberValue).length === 0;
				case "keyEncryptionAlgorithm":
				case "encryptedKey":
					return memberValue.isEqual(KeyTransRecipientInfo.defaultValues(memberName));
				case "recipientCertificate":
					return false; // For now we do not need to compare any values with the "recipientCertificate"
				default:
					throw new Error("Invalid member name for KeyTransRecipientInfo class: " + memberName);
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

			//KeyTransRecipientInfo ::= SEQUENCE {
			//    version CMSVersion,  -- always set to 0 or 2
			//    rid RecipientIdentifier,
			//    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
			//    encryptedKey EncryptedKey }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [rid]
    * @property {string} [keyEncryptionAlgorithm]
    * @property {string} [encryptedKey]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), _RecipientIdentifier2.default.schema(names.rid || {}), _AlgorithmIdentifier2.default.schema(names.keyEncryptionAlgorithm || {}), new asn1js.OctetString({ name: names.encryptedKey || "" })]
			});
		}
	}]);

	return KeyTransRecipientInfo;
}();
//**************************************************************************************


exports.default = KeyTransRecipientInfo;
//# sourceMappingURL=KeyTransRecipientInfo.js.map