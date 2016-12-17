"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _OriginatorIdentifierOrKey = require("./OriginatorIdentifierOrKey");

var _OriginatorIdentifierOrKey2 = _interopRequireDefault(_OriginatorIdentifierOrKey);

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _RecipientEncryptedKeys = require("./RecipientEncryptedKeys");

var _RecipientEncryptedKeys2 = _interopRequireDefault(_RecipientEncryptedKeys);

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var KeyAgreeRecipientInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for KeyAgreeRecipientInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function KeyAgreeRecipientInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, KeyAgreeRecipientInfo);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description version
   */
		this.version = (0, _pvutils.getParametersValue)(parameters, "version", KeyAgreeRecipientInfo.defaultValues("version"));
		/**
   * @type {OriginatorIdentifierOrKey}
   * @description originator
   */
		this.originator = (0, _pvutils.getParametersValue)(parameters, "originator", KeyAgreeRecipientInfo.defaultValues("originator"));

		if ("ukm" in parameters)
			/**
    * @type {OctetString}
    * @description ukm
    */
			this.ukm = (0, _pvutils.getParametersValue)(parameters, "ukm", KeyAgreeRecipientInfo.defaultValues("ukm"));

		/**
   * @type {AlgorithmIdentifier}
   * @description keyEncryptionAlgorithm
   */
		this.keyEncryptionAlgorithm = (0, _pvutils.getParametersValue)(parameters, "keyEncryptionAlgorithm", KeyAgreeRecipientInfo.defaultValues("keyEncryptionAlgorithm"));
		/**
   * @type {RecipientEncryptedKeys}
   * @description recipientEncryptedKeys
   */
		this.recipientEncryptedKeys = (0, _pvutils.getParametersValue)(parameters, "recipientEncryptedKeys", KeyAgreeRecipientInfo.defaultValues("recipientEncryptedKeys"));
		/**
   * @type {Certificate}
   * @description recipientCertificate For some reasons we need to store recipient's certificate here
   */
		this.recipientCertificate = (0, _pvutils.getParametersValue)(parameters, "recipientCertificate", KeyAgreeRecipientInfo.defaultValues("recipientCertificate"));
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


	_createClass(KeyAgreeRecipientInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, KeyAgreeRecipientInfo.schema({
				names: {
					version: "version",
					originator: {
						names: {
							blockName: "originator"
						}
					},
					ukm: "ukm",
					keyEncryptionAlgorithm: {
						names: {
							blockName: "keyEncryptionAlgorithm"
						}
					},
					recipientEncryptedKeys: {
						names: {
							blockName: "recipientEncryptedKeys"
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for KeyAgreeRecipientInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.version = asn1.result.version.valueBlock.valueDec;
			this.originator = new _OriginatorIdentifierOrKey2.default({ schema: asn1.result.originator });

			if ("ukm" in asn1.result) this.ukm = asn1.result.ukm;

			this.keyEncryptionAlgorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.keyEncryptionAlgorithm });
			this.recipientEncryptedKeys = new _RecipientEncryptedKeys2.default({ schema: asn1.result.recipientEncryptedKeys });
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
			//region Create array for final sequence
			var outputArray = [];

			outputArray.push(new asn1js.Integer({ value: this.version }));
			outputArray.push(new asn1js.Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [this.originator.toSchema()]
			}));

			if ("ukm" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [this.ukm]
				}));
			}

			outputArray.push(this.keyEncryptionAlgorithm.toSchema());
			outputArray.push(this.recipientEncryptedKeys.toSchema());
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
			var _object = {
				version: this.version,
				originator: this.originator.toJSON()
			};

			if ("ukm" in this) _object.ukm = this.ukm.toJSON();

			_object.keyEncryptionAlgorithm = this.keyEncryptionAlgorithm.toJSON();
			_object.recipientEncryptedKeys = this.recipientEncryptedKeys.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "version":
					return 0;
				case "originator":
					return new _OriginatorIdentifierOrKey2.default();
				case "ukm":
					return new asn1js.OctetString();
				case "keyEncryptionAlgorithm":
					return new _AlgorithmIdentifier2.default();
				case "recipientEncryptedKeys":
					return new _RecipientEncryptedKeys2.default();
				case "recipientCertificate":
					return new _Certificate2.default();
				default:
					throw new Error("Invalid member name for KeyAgreeRecipientInfo class: " + memberName);
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
					return memberValue === 0;
				case "originator":
					return memberValue.variant === -1 && "value" in memberValue === false;
				case "ukm":
					return memberValue.isEqual(KeyAgreeRecipientInfo.defaultValues("ukm"));
				case "keyEncryptionAlgorithm":
					return memberValue.algorithmId === "" && "algorithmParams" in memberValue === false;
				case "recipientEncryptedKeys":
					return memberValue.encryptedKeys.length === 0;
				case "recipientCertificate":
					return false; // For now leave it as is
				default:
					throw new Error("Invalid member name for KeyAgreeRecipientInfo class: " + memberName);
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

			//KeyAgreeRecipientInfo ::= SEQUENCE {
			//    version CMSVersion,  -- always set to 3
			//    originator [0] EXPLICIT OriginatorIdentifierOrKey,
			//    ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
			//    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
			//    recipientEncryptedKeys RecipientEncryptedKeys }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [version]
    * @property {string} [originator]
    * @property {string} [ukm]
    * @property {string} [keyEncryptionAlgorithm]
    * @property {string} [recipientEncryptedKeys]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.version || "" }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [_OriginatorIdentifierOrKey2.default.schema(names.originator || {})]
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.OctetString({ name: names.ukm || "" })]
				}), _AlgorithmIdentifier2.default.schema(names.keyEncryptionAlgorithm || {}), _RecipientEncryptedKeys2.default.schema(names.recipientEncryptedKeys || {})]
			});
		}
	}]);

	return KeyAgreeRecipientInfo;
}();
//**************************************************************************************


exports.default = KeyAgreeRecipientInfo;
//# sourceMappingURL=KeyAgreeRecipientInfo.js.map