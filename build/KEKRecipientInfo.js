"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _KEKIdentifier = require("./KEKIdentifier");

var _KEKIdentifier2 = _interopRequireDefault(_KEKIdentifier);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var KEKRecipientInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for KEKRecipientInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function KEKRecipientInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, KEKRecipientInfo);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", KEKRecipientInfo.defaultValues("version"));
		/**
   * @type {KEKIdentifier}
   * @description kekid
   */
		this.kekid = (0, _pvutils.getParametersValue)(parameters, "kekid", KEKRecipientInfo.defaultValues("kekid"));
		/**
   * @type {AlgorithmIdentifier}
   * @description keyEncryptionAlgorithm
   */
		this.keyEncryptionAlgorithm = (0, _pvutils.getParametersValue)(parameters, "keyEncryptionAlgorithm", KEKRecipientInfo.defaultValues("keyEncryptionAlgorithm"));
		/**
   * @type {OctetString}
   * @description encryptedKey
   */
		this.encryptedKey = (0, _pvutils.getParametersValue)(parameters, "encryptedKey", KEKRecipientInfo.defaultValues("encryptedKey"));
		/**
   * @type {ArrayBuffer}
   * @description preDefinedKEK KEK using to encrypt CEK
   */
		this.preDefinedKEK = (0, _pvutils.getParametersValue)(parameters, "preDefinedKEK", KEKRecipientInfo.defaultValues("preDefinedKEK"));
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


	_createClass(KEKRecipientInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, KEKRecipientInfo.schema({
				names: {
					version: "version",
					kekid: {
						names: {
							blockName: "kekid"
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

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for KEKRecipientInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;
			this.kekid = new _KEKIdentifier2.default({ schema: asn1.result.kekid });
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
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: [new asn1js.Integer({ value: this.version }), this.kekid.toSchema(), this.keyEncryptionAlgorithm.toSchema(), this.encryptedKey]
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
				kekid: this.originator.toJSON(),
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
					return 0;
				case "kekid":
					return new _KEKIdentifier2.default();
				case "keyEncryptionAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "encryptedKey":
					return new asn1js.OctetString();
				case "preDefinedKEK":
					return new ArrayBuffer(0);
				default:
					throw new Error("Invalid member name for KEKRecipientInfo class: " + memberName);
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
				case "KEKRecipientInfo":
					return memberValue === KEKRecipientInfo.defaultValues("version");
				case "kekid":
					return memberValue.compareWithDefault("keyIdentifier", memberValue.keyIdentifier) && "date" in memberValue === false && "other" in memberValue === false;
				case "keyEncryptionAlgorithm":
					return memberValue.algorithmId === "" && "algorithmParams" in memberValue === false;
				case "encryptedKey":
					return memberValue.isEqual(KEKRecipientInfo.defaultValues("encryptedKey"));
				case "preDefinedKEK":
					return memberValue.byteLength === 0;
				default:
					throw new Error("Invalid member name for KEKRecipientInfo class: " + memberName);
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

			//KEKRecipientInfo ::= SEQUENCE {
			//    version CMSVersion,  -- always set to 4
			//    kekid KEKIdentifier,
			//    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
			//    encryptedKey EncryptedKey }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [kekid]
    * @property {string} [keyEncryptionAlgorithm]
    * @property {string} [encryptedKey]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), _KEKIdentifier2.default.schema(names.kekid || {}), _AlgorithmIdentifier2.default.schema(names.keyEncryptionAlgorithm || {}), new asn1js.OctetString({ name: names.encryptedKey || "" })]
			});
		}
	}]);

	return KEKRecipientInfo;
}();
//**************************************************************************************


exports.default = KEKRecipientInfo;
//# sourceMappingURL=KEKRecipientInfo.js.map